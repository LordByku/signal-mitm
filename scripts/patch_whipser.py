import subprocess
import os
import logging
import shutil
import sys

# Initialize logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

bc_jar_path = os.path.realpath("scripts/bcprov-jdk18on-1.78.1.jar")


def check_keytool_exists():
    """Check if keytool exists in the PATH."""
    return shutil.which("keytool") is not None


def print_certificate_details(keystore_path, keystore_password, alias):
    """Print certificate details for a given alias in the keystore."""
    print_command = ["keytool", "-exportcert", "-keystore", keystore_path,
                     "-storepass", keystore_password, "-alias", alias, "-rfc",
                     "-storetype", "BKS",
                     "-provider", "org.bouncycastle.jce.provider.BouncyCastleProvider", "-providerpath", bc_jar_path]
    try:
        cert = subprocess.check_output(print_command, stderr=subprocess.STDOUT, universal_newlines=True)
        logging.info(f"Certificate details for alias '{alias}':\n{cert}")
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to print certificate details: {e.output}")
        exit(-1)


def replace_ca_in_keystore(keystore_path, keystore_password, new_ca_path, ca_alias):
    # Check if keytool exists
    if not check_keytool_exists():
        logging.error(
            "keytool could not be found. Please ensure the Java Development Kit (JDK) is installed and keytool is in "
            "your PATH. Visit https://www.oracle.com/java/technologies/downloads/ (or your distribution's wiki) for "
            "more details.")
        exit(-1)

    # Print old CA certificate details
    logging.info("Old CA certificate details:")
    print_certificate_details(keystore_path, keystore_password, ca_alias)

    # Delete the existing CA certificate
    delete_command = ["keytool", "-delete", "-alias", ca_alias, "-keystore", keystore_path, "-storepass",
                      keystore_password, "-storetype", "BKS",
                      "-provider", "org.bouncycastle.jce.provider.BouncyCastleProvider", "-providerpath", bc_jar_path]
    try:
        subprocess.check_call(delete_command, stderr=subprocess.STDOUT)
        logging.info("Existing CA certificate deleted successfully.")
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to delete existing CA: {e.output}")
        exit(-1)

    # Import the new CA certificate
    import_command = ["keytool", "-import", "-alias", ca_alias, "-file", new_ca_path, "-keystore", keystore_path,
                      "-noprompt", "-storepass", keystore_password, "-storetype", "BKS",
                      "-provider", "org.bouncycastle.jce.provider.BouncyCastleProvider", "-providerpath", bc_jar_path]
    try:
        subprocess.check_call(import_command, stderr=subprocess.STDOUT)
        logging.info("New CA certificate imported successfully.")
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to import new CA: {e.output}")
        exit(-1)

    # Print new CA certificate details
    logging.info("New CA certificate details:")
    print_certificate_details(keystore_path, keystore_password, ca_alias)
    logging.info("DONE ^^")


# Paths, password, and alias
keystore_path = sys.argv[1]
keystore_password = "whisper"  # Placeholder password, adjust as needed
mitmproxy_ca_path = os.path.expanduser("~/.mitmproxy/mitmproxy-ca-cert.cer")
ca_alias = "signal-messenger-ca"  # Adjust accordingly for your needs

# Perform the CA replacement in the keystore
replace_ca_in_keystore(keystore_path, keystore_password, mitmproxy_ca_path, ca_alias)
