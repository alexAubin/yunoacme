#!/usr/bin/python2.7
# -*- coding: utf-8 -*-

import sys, os, pwd, grp, logging, requests, glob, subprocess, shutil
from datetime import datetime
from OpenSSL  import crypto
from optparse import OptionParser
from tabulate import tabulate
from lib.acme_tiny.acme_tiny import get_crt as signCertificate

###############################################################################
#   Misc definitions                                                          #
###############################################################################

# Where Yunohost keeps the certs
yunohostCertsFolder = "/etc/yunohost/certs/"

# Where we keep the yunoacme / letsencrypt stuff
confFolder          = "/etc/yunoacme/"

# Where we keep temporary files, and the webroot used to verify the domain when signing the certs
tmpFolder           = "/tmp/yunoacme/"
webrootFolder       = "/tmp/yunoacme-challenge/"

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

        if ((options.installAll) or (options.install)) :

            if (options.install) :
                domainsToInstall = [options.install]
            else :

                domainsToInstall = []

                for domain in getNginxDomainsList() :

                    status        = getStatus(domain)
                    statusSummary = status[1]
                    issuer        = status[2]

                    # FIXME : remove Fake LE after dev
                    if (not issuer.startswith("Let's Encrypt")) and (not issuer.startswith("Fake LE")) and (statusSummary != "OK") :
                        domainsToInstall.append(domain)

            for domain in domainsToInstall :

                try :
                    install(domain, options.force)

                except Exception as e :

                    logger.error(str(e))
                    logger.error("-----------------------------------")
                    logger.error("Installation for "+domain+" failed!")
                    logger.error("-----------------------------------")

        # ============
        # Renew
        # ============

        if ((options.renewAll) or (options.renew)) :

            if (options.renew) :
                domainsToRenew = [options.renew]
            else :
                domainsToRenew = []

                for domain in getNginxDomainsList() :

                    issuer = getStatus(domain)[2]
                    if (issuer.startswith("Let's Encrypt")) :
                        domainsToRenew.append(domain)

            for domain in domainsToRenew :

                try :
                    renew(domain, options.force)

                except Exception as e :

                    logger.error(str(e))
                    logger.error("-------------------------------")
                    logger.error("Renewing for "+domain+" failed!")
                    logger.error("-------------------------------")

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

        makeDir(confFolder,           "root", "root",      0655);
        makeDir(confFolder+"/certs/", "root", "metronome", 0650);
        makeDir(confFolder+"/keys/",  "root", "root",      0600);
        makeDir(confFolder+"/live/",  "root", "metronome", 0650);
        makeDir(confFolder+"/logs/",  "root", "root",      0600);

        addKey("account", confFolder+"/keys/")

        print("OK.")

###############################################################################

def getStatus(domain) :

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
    # FIXME : remove me after dev
    elif (issuedBy.startswith("Fake LE")) :
        statusSummary = "GOOD"
    else :
        # FIXME : should probably think about a better definition for this
        knownCAs = [ "StartCom" ]
        for CA in knownCAs :
            if (issuedBy.startswith(CA)) :
                statusSummary = "OK"
                break

    returnValue = [ domain, statusSummary, issuedBy, daysRemaining ]

    return returnValue

###############################################################################

def install(domain, force) :

    # Check that it makes sense to install a LE cert on this domain

    validateDomain(domain)

    status        = getStatus(domain)
    statusSummary = status[1]
    issuer        = status[2]

    if (issuer.startswith("Let's Encrypt")) :
        logger.warning("Domain "+domain+" seems to already have a Let's Encrypt certificate, ignoring.")
        return

    if (not force) and (statusSummary == "OK") :
        logger.warning("Domain "+domain+" seems to already have a valid certificate, ignoring.")
        logger.warning("(Use --force to bypass.)")
        return
    
    # Ask user confirmation

    confirm(" /!\ WARNING /!\ \nThis script will now attempt to install Let's Encrypt certificate for domain "+domain+ " !")

    print("===========================================================")
    print("Attempting to install certificate for domain "+domain+" ...")
    print("===========================================================")

    # Backup existing certificate

    logger.info("Backuping existing certificate in "+confFolder+"/certs/")

    dateTag = datetime.now().strftime("%Y%m%d.%H%M%S")
    backupFolder = confFolder+"/certs/"+domain+"."+dateTag+"-backupPreviousCertificate"
    shutil.copytree(yunohostCertsFolder+"/"+domain, backupFolder)

    # Configure nginx and ssowat for acme challenge

    logger.info("Configuring Nginx and SSOWat for ACME challenge on "+domain+" ...")

    configureNginxAndSsowatForAcmeChallenge(domain)

    fetchAndEnableNewCertificate(domain)

    print("===================================================")
    print("Certificate for "+domain+" successfully installed !")
    print("===================================================")

###############################################################################

def renew(domain, force) :

    # Check that it makes sense to renew the cert for this domain

    validateDomain(domain)

    status        = getStatus(domain)
    statusSummary = status[1]
    issuer        = status[2]
    validity      = status[3]

    # FIXME : Remove Fake LE after dev is done
    if (not issuer.startswith("Let's Encrypt")) and (not issuer.startswith("Fake LE")) :
        logger.warning("Domain "+domain+" does not have a Let's Encrypt certificate, ignoring.")
        return

    if (not force) and (validity > validityLimit) :
        logger.info("Certificate for "+domain+" is still valid for "+str(validity)+" days, skipping.")
        logger.info("(Use --force to bypass the "+str(validityLimit)+" days validity threshold.)")
        return
 
    # Ask user confirmation
    
    confirm(" /!\ WARNING /!\ \nThis script will now attempt to renew certificate for domain "+domain+ " !")

    # Actually renew the cert

    print("=========================================================")
    print("Attempting to renew certificate for domain "+domain+" ...")
    print("=========================================================")
    
    fetchAndEnableNewCertificate(domain)

    print("=================================================")
    print("Certificate for "+domain+" successfully renewed !")
    print("=================================================")

###############################################################################

def fetchAndEnableNewCertificate(domain) :


    logger.info("Making sure tmp folders exists...")

    makeDir(webrootFolder, "root", "www-data", 0650);
    makeDir(tmpFolder,     "root", "root",     0640);



    logger.info("Prepare key and certificate signing request (CSR) for "+domain+"...")

    addKey(domain, tmpFolder)
    domainKeyFile = tmpFolder+"/"+domain+".pem"

    prepareCertificateSigningRequest(domain, domainKeyFile, tmpFolder)



    logger.info("Now using ACME Tiny to sign the certificate...")

    accountKeyFile = confFolder+"/keys/account.pem"
    domainCsrFile  = tmpFolder+"/"+domain+".csr"

    signedCertificate = signCertificate(accountKeyFile, domainCsrFile, webrootFolder, log=logger)
    LEintermediateCertificate = requests.get("https://letsencrypt.org/certs/lets-encrypt-x3-cross-signed.pem").text



    logger.info("Saving the key and signed certificate...")

    # Create corresponding directory
    dateTag = datetime.now().strftime("%Y%m%d.%H%M%S")
    newCertFolder = confFolder + "/certs/" + domain + "." + dateTag
    makeDir(newCertFolder,     "root", "root",     0655);

    # Move the private key
    shutil.move(domainKeyFile, newCertFolder+"/key.pem")

    # Write the cert
    with open(newCertFolder+"/crt.pem", "w") as f :
        f.write(signedCertificate)
        f.write(LEintermediateCertificate)



    logger.info("Enabling the new certificate...")

    # Replace (if necessary) the link in live folder
    liveLink = confFolder+"/live/"+domain

    if os.path.lexists(liveLink) :
        os.remove(liveLink)

    os.symlink(newCertFolder, liveLink)

    # Check the path in yunohost cert folder points to something in the yunoacme conf folder
    yunohostCertFolderDomain = yunohostCertsFolder+"/"+domain
    if not (os.path.realpath(yunohostCertFolderDomain).startswith(confFolder)) :

        # If not, we delete it (should have been backuped during install())
        # and make it point to the live folder
        shutil.rmtree(yunohostCertFolderDomain)
        os.symlink(liveLink, yunohostCertFolderDomain)

    # Check the status of the certificate is now "GOOD"
    status        = getStatus(domain)
    statusSummary = status[1]
    if (statusSummary != "GOOD") :
        raise Exception("Sounds like enabling the new certificate for "+domain+" failed somehow... (status is not 'GOOD') ='(")



    logging.info("Restarting services...")

    for s in [ "nginx", "postfix", "dovecot", "metronome" ] :

        service(s, "restart")




###############################################################################
#   Misc tools                                                                #
###############################################################################

def confirm(message) :

    print(message)

    try :

        r = raw_input("Is this what you want (type 'yes', or use Ctrl+C to abort) ? ").lower()
        while (r != 'yes') :
            r = raw_input("Please either type 'yes', or use Ctrl+C. ").lower()

    except KeyboardInterrupt:

        print("\nAborting.")
        sys.exit()

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
        alias        '''+webrootFolder+''';
}
    '''

    # Check domain.d folder exists
    domainConfFolder = os.path.dirname(nginxConfFile)
    if not os.path.exists(domainConfFolder) :
        raise Exception("Folder " + domainConfFolder + " does not exists. If you know what you are doing, please create it manually to continue.")

    # Write the conf
    if os.path.exists(nginxConfFile) :

        logger.info("Nginx configuration file for ACME challenge already exists for domain, skipping.")

    else :

        logger.info("Adding Nginx configuration file for Let's encrpt / Acme challenge for domain " + domain + ".")
        with open(nginxConfFile, "w") as f :
            f.write(nginxConfiguration)

        # Check conf is okay and reload nginx if it is
        if (checkNginxConfiguration()) :
            service("nginx","reload")

    # SSOwat part
    # -----------

        # Get current unprotected regex for the domain

    command = "sudo yunohost app setting letsencrypt unprotected_regex"
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)
    process.wait()
    regexList, err = process.communicate()

        # Append regex for 'domain' to the current list

    regex = domain+"/%.well%-known/acme%-challenge/.*$"

    if regex in regexList :

        logger.info("Let's encrypt / Acme challenge SSOWat configuration already in place, skipping.")

    else :
        logger.info("Adding SSOWat configuration for Let's encrypt / ACME challenge for domain " + domain + ".")

        regexList += ","+regex

        command = "sudo yunohost app setting letsencrypt unprotected_regex -v \""+regexList+"\""
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)
        process.wait()

            # Update SSOwat conf

        command = "sudo yunohost app ssowatconf"
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)
        process.wait()

###############################################################################

def prepareCertificateSigningRequest(domain, keyFile, outputFolder) :

    # Init a request
    csr = crypto.X509Req()

    # Set the domain
    csr.get_subject().CN = domain

    # Set the key
    with open(keyFile, 'rt') as f :
        key = crypto.load_privatekey(crypto.FILETYPE_PEM, f.read())
    csr.set_pubkey(key)

    # Sign the request
    csr.sign(key, "sha256")

    # Save the request in tmp folder
    csrFile = outputFolder+domain+".csr"
    logger.info("Saving to "+csrFile+" .")
    with open(csrFile, "w") as f :
        f.write(crypto.dump_certificate_request(crypto.FILETYPE_PEM, csr))

###############################################################################

def initLogger(level=logging.INFO) :

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

        if (domain == "yunohost_admin") or (domain == "ssowat") or (domain == "global") :
            continue

        domainList.append(domain)

    return domainList

###############################################################################

def checkNginxConfiguration() :

    command = "sudo nginx -t"
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)
    process.wait()

    if (process.returncode != 0) :
        raise Exception("This program seems to have broken the nginx configuration! Sorry about that. :( Check the output of the 'nginx -t' command.")
        return False
    else :
        return True

###############################################################################

def addKey(name, outputFolder) :

    keyFile = outputFolder+"/"+name+".pem"

    k = crypto.PKey()
    logger.info("Generating private "+name+" key ...")
    k.generate_key(crypto.TYPE_RSA, 2048)

    logger.info("Saving key.")
    with open(keyFile, "w") as f :
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k))

###############################################################################

def validateDomain(domain) :

    logger.debug("Attempting to validate domain "+domain+" ...")

    # Check domain is configured in yunohost ?
    if (domain not in getNginxDomainsList()) :
        raise Exception("Domain "+domain+" is not configured in your yunohost installation!")

    # Check it's possible to access domain on port 80 ?
    try :

        requests.head("http://"+domain)
        logger.debug("Domain "+domain+" seems good to work with !")
        return True

    except Exception:

        raise Exception("It seems that domain "+domain+" cannot be accessed on port 80? Please check your configuration.")
        return False

###############################################################################

def makeDir(path, user, group, permissions) :

    if os.path.exists(path) :
        logger.info("Folder "+path+" already exists, skipping creation.")
    else :
        os.makedirs(path);

    uid = pwd.getpwnam(user).pw_uid
    gid = grp.getgrnam(group).gr_gid

    os.chown(path, uid, gid)
    os.chmod(path, permissions)

###############################################################################

def service(theService, whatDo) :

    command = "sudo service "+theService+" "+whatDo
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)
    process.wait()


###############################################################################

if __name__ == "__main__":
    main()

