#!/usr/bin/python2.7
# -*- coding: utf-8 -*-

import os, pwd, grp, logging, requests, glob, subprocess
from datetime import datetime
from OpenSSL  import crypto
from optparse import OptionParser
from tabulate import tabulate
from lib.acme_tiny.acme_tiny import get_crt as fetchCertificate

###############################################################################
#   Misc definitions                                                          #
###############################################################################

# Where Yunohost keeps the certs
yunohostCertsFolder = "/etc/yunohost/certs/"

# Where we keep the yunoacme / letsencrypt stuff
confFolder          = "/etc/yunoacme/"

# Where we keep temporary files, and the webroot used to verify the domain when signing the certs
tmpFolder           = "/tmp/yunoacme/"

# The validity limit, in days, after which we should be renewing certs
validityLimit       = 15

###############################################################################
#  Dah main.                                                                  #
###############################################################################

logger = logging.getLogger(__name__)

def main() :
    
    init()

    # Start logger
    initLogger()
    logger = logging.getLogger(__name__)

    try :

        # Let's see what the user wants
        options = parseOptions()
    
        # ============
        # Status check
        # ============

        if ((options.statusAll) or (options.status)) :

            if (options.status) :
                domainsToCheck = [options.status]
            else :
                domainsToCheck = getNginxDomainsList()

            headers = [ "Domain", "Certificate status", "Authority", "Days remaining" ]
            status = []
            for domain in domainsToCheck :
                status.append(getStatus(domain))
           
            print(tabulate(status, headers=headers, tablefmt="simple", stralign="center"))

        # ============
        # Install
        # ============
        
        if (options.install) :
            
            domain = options.install
            install(domain)

    except Exception as e :

        logger.error(str(e))

###############################################################################

def parseOptions() :

    parser = OptionParser()

    parser.add_option("-i", "--install",
                      metavar="domain.tld",
                      dest="install",
                      help="Configure a given domain to fetch and use a Let's Encrypt certificate.")

    parser.add_option("-I", "--install-all",
                      dest="installAll",
                      default=False,
                      action="store_true",
                      help="Like -i, but for each domain with no Let's encrypt certificate.")

    parser.add_option("-s", "--status",
                      metavar="domain.tld",
                      dest="status",
                      help="List each yunohost domains and the status of its associated certificate.")

    parser.add_option("-S", "--status-all",
                      dest="statusAll",
                      default=False,
                      action="store_true",
                      help="List all domains and the status of its associated certificate.")

    parser.add_option("-r", "--renew",
                      metavar="domain.tld",
                      dest="renew",
                      help="Renew the certificate for a given domain if its validity is below "+str(validityLimit)+" days.")

    parser.add_option("-R", "--renew-all",
                      dest="renewAll",
                      default=False,
                      action="store_true",
                      help="Like -r, but for each domain with a Let's encrypt certificate.")

    parser.add_option("-f", "--force",
                      dest="force",
                      default=False,
                      action="store_true",
                      help="To be used with -r and -R : renew the certificate regardless of the remaining validity.")

    parser.add_option("-l", "--logs",
                      dest="logs",
                      default=False,
                      action="store_true",
                      help="Shows the logs.")

    (options, args) = parser.parse_args()

    if ((options.install) and (options.installAll)) :
        parser.error("Options -i and -I are mutually exclusive.")
    if ((options.status) and (options.statusAll)) :
        parser.error("Options -s and -S are mutually exclusive.")
    if ((options.renew) and (options.renewAll)) :
        parser.error("Options -r and -R are mutually exclusive.")

    return options

###############################################################################
#   'High-level' functions                                                    #
###############################################################################

def init() :
        
    if not os.path.exists(confFolder):
    
        print("Initial configuration and folders not there yet, creating them...")
        
        rootId      = pwd.getpwnam("root").pw_uid
        metronomeId = grp.getgrnam("metronome").gr_gid
        
        makeDir(confFolder,           "root", "root",      0640);
        makeDir(confFolder+"/certs/", "root", "metronome", 0640);
        makeDir(confFolder+"/keys/",  "root", "root",      0640);
        makeDir(confFolder+"/live/",  "root", "metronome", 0640);
        makeDir(confFolder+"/logs/",  "root", "root",      0640);

        addKey("account")
        
        print("OK.")

###############################################################################

def getStatus(domain) :

    logger.debug("Checking status of certificate for domain "+domain+"...")
    
    certFile = yunohostCertsFolder+"/"+domain+"/crt.pem"
    cert = crypto.load_certificate(crypto.FILETYPE_PEM, open(certFile).read())
    issuedBy = cert.get_issuer().CN
    validUpTo = datetime.strptime(cert.get_notAfter(),"%Y%m%d%H%M%SZ")
    daysRemaining = (validUpTo - datetime.now()).days
    
    statusSummary = "UNKNOWN"

    if (daysRemaining < 0) :
        statusSummary = "BAD"
    elif (daysRemaining < validityLimit) :
        statusSummary = "WARNING"
    elif (issuedBy.startswith("Let's Encrypt")) :
        statusSummary = "GOOD"
    else :
        # FIXME : should probably think about a better definition for this
        knownCAs = [ "StartCom" ]
        for CA in knownCAs :
            if (issuedBy.startswith(CA)) :
                statusSummary = "OK"
                break
    
    returnValue = [ domain, statusSummary, issuedBy, daysRemaining ]

    logger.debug(returnValue)

    return returnValue

###############################################################################

def install(domain) :

    # Check that it makes sense to install a LE cert on this domain 
    validateDomain(domain)

    status        = getStatus(domain)
    statusSummary = status[1]
    issuer        = status[2]
    if (statusSummary == "GOOD") or (issuer.startswith("Let's Encrypt")) :
        raise Exception("This domain seems to already have a valid Let's Encrypt certificate?")
    
    logger.info("Configuring Nginx and SSOWat for ACME challenge on "+domain+" ...")
    configureNginxAndSsowatForAcmeChallenge(domain)

    addKey(domain)

    logger.info("Prepare certificate signing request (CSR) for "+domain+"...")
    prepareCertificateSigningRequest(domain)

    logger.info("Now asking ACME Tiny to fetch the certificate...")

    accountKeyFile = confFolder+"/keys/account.pem"
    # FIXME remove if not needed later
    #domainKeyFile  = confFolder+"/keys/"+domain+".pem"
    domainCsrFile  = tmpFolder+"/"+domain+".csr"

    signedCertificate = fetchCertificate(accountKeyFile, domainCsrFile, tmpFolder, log=logger)
    print signedCertificate
    
    LEintermediateCertificate = requests.get("https://letsencrypt.org/certs/lets-encrypt-x3-cross-signed.pem").text
    print LEintermediateCertificate

    with open("./tmp", "w") as f :
        f.write(signedCertificate)
        f.write(LEintermediateCertificate)

###############################################################################
#   Misc tools                                                                #
###############################################################################

# FIXME : probably split this in several functions
def configureNginxAndSsowatForAcmeChallenge(domain) :

    # Nginx part
    # -----------

    nginxConfFile = "/etc/nginx/conf.d/"+domain+".d/000-acmechallenge.conf"

    nginxConfiguration = '''
location '/.well-known/acme-challenge' 
{
        default_type "text/plain";
        alias        '''+tmpFolder+''';
}
    '''

    # Check domain.d folder exists
    domainConfFolder = os.path.dirname(nginxConfFile)
    if not os.path.exists(domainConfFolder) :
        raise Exception("Folder " + domainConfFolder + " does not exists. If you know what you are doing, please create it manually to continue.")

    # Write the conf
    if os.path.exists(nginxConfFile) :
        
        logger.info("Nginx configuration file for Let's encrypt / Acme challenge already exists, skipping.")
       
    else :
        
        logger.info("Adding Nginx configuration file for Let's encrpt / Acme challenge for domain " + domain + ".")
        with open(nginxConfFile, "w") as f :
            f.write(nginxConfiguration)
        
        # Check conf is okay and reload nginx if it is
        if (checkNginxConfiguration()) :
            command = "systemctl reload nginx"
            process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)
            process.wait()
        
    # SSOwat part
    # -----------

        # Get current unprotected regex for the domain

    command = "yunohost app setting letsencrypt unprotected_regex"
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)
    process.wait()
    regexList, err = process.communicate()
   
        # Append regex for 'domain' to the current list

    regex = domain+"/%.well%-known/acme%-challenge/.*$"
    
    if regex in regexList :
    
        logger.info("Let's encrypt / Acme challenge SSOWat configartion already in place, skipping.")
    
    else :
        logger.info("Adding SSOWat configuration for Let's encrpt / Acme challenge for domain " + domain + ".")

        regexList += ","+regex
        
        command = "yunohost app setting letsencrypt unprotected_regex -v \""+regexList+"\""
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)
        process.wait()

            # Update SSOwat conf

        command = "yunohost app ssowatconf"
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)
        process.wait()

    # Make sure the tmp / webroot folder exists
    # -----------------------------------
    
    if os.path.exists(tmpFolder) :
        
        logger.info("Webroot folder already exists, skipping.")

    else :
        
        makeDir(tmpFolder, "root", "www-data", 0650);

###############################################################################

def prepareCertificateSigningRequest(domain) :
        
    # Init a request
    csr = crypto.X509Req()
    
    # Set the domain
    csr.get_subject().CN = domain
    
    # Set the key
    with open(confFolder+"/keys/"+domain+".pem", 'rt') as f :
        key = crypto.load_privatekey(crypto.FILETYPE_PEM, f.read())
    csr.set_pubkey(key)
    
    # Sign the request
    csr.sign(key, "sha256")
    
    # Save the request in tmp folder
    csrFile = tmpFolder+domain+".csr"
    logger.info("Saving to "+csrFile+" .")
    with open(csrFile, "w") as f :
        f.write(crypto.dump_certificate_request(crypto.FILETYPE_PEM, csr))

###############################################################################

def initLogger(level=logging.DEBUG) :

    # Name, format and level
    formatter = logging.Formatter('[%(levelname)s] %(asctime)s : %(message)s',
            datefmt='%d/%m/%y %H:%M:%S')
    logger.setLevel(level)
    
    # Logging to a file
    fileHandler = logging.FileHandler(confFolder+"/logs/logs")
    fileHandler.setFormatter(formatter)
    logger.addHandler(fileHandler)

    # Logging to stdout / stderr
    streamHandler = logging.StreamHandler()
    streamHandler.setFormatter(formatter)
    logger.addHandler(streamHandler)    

###############################################################################

def getNginxDomainsList() :
    
    g = glob.glob("/etc/nginx/conf.d/*.conf")

    domainList = []

    for path in g :

        domain = os.path.basename(path)[:-5]

        if (domain == "yunohost_admin") or (domain == "ssowat") :
            continue

        domainList.append(domain)

    return domainList

###############################################################################

def checkNginxConfiguration() :

    command = "nginx -t"
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)
    process.wait()

    if (process.returncode != 0) :
        raise Exception("This program seems to have broken the nginx configuration! Sorry about that. :( Check the output of the 'nginx -t' command.")
        return False
    else :
        return True

###############################################################################

def addKey(name) :

    keyFile = confFolder+"/keys/"+name+".pem"

    if os.path.exists(keyFile) :
        
        logger.info("Private key for "+name+" already exists, skipping.")

    else :

        k = crypto.PKey()
        logger.info("Generating private "+name+" key ...")
        k.generate_key(crypto.TYPE_RSA, 2048)

        logger.info("Saving key.")
        with open(keyFile, "w") as f :
            f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k))

###############################################################################

def validateDomain(domain) :

    logger.info("Attempting to validate domain "+domain+" ...")

    # Check domain is configured in yunohost ?
    if (domain not in getNginxDomainsList()) :
        raise Exception("Domain "+domain+" is not configured in your yunohost installation!")

    # Check it's possible to access domain on port 80 ?
    try :

        requests.head("http://"+domain)
        logger.info("Domain "+domain+" seems good to work with !")
        return True

    except Exception:

        raise Exception("It seems that domain "+domain+" cannot be accessed on port 80? Please check your configuration.")
        return False
 
###############################################################################

def makeDir(path, user, group, permissions) :

    uid = pwd.getpwnam(user).pw_uid
    gid = grp.getgrnam(group).gr_gid
        
    os.makedirs(path);
    os.chown(path, uid, gid)
    os.chmod(path, permissions)

###############################################################################

if __name__ == "__main__":
    main()

