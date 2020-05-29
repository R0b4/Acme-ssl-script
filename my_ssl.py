print("\nAAA\n")

from contextlib import contextmanager

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
import josepy as jose
import OpenSSL

from acme import challenges
from acme import client
from acme import crypto_util
from acme import errors
from acme import messages
from acme import standalone

import os

def new_csr_comp(domain_name, pkey_pem=None):
    """Create certificate signing request."""
    if pkey_pem is None:
        # Create private key.
        pkey = OpenSSL.crypto.PKey()
        pkey.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)
        pkey_pem = OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, pkey)
    csr_pem = crypto_util.make_csr(pkey_pem, [domain_name])
    return pkey_pem, csr_pem

def select_http01_chall(orderr):
    """Extract authorization resource from within order resource."""
    # Authorization Resource: authz.
    # This object holds the offered challenges by the server and their status.
    authz_list = orderr.authorizations

    for authz in authz_list:
        # Choosing challenge.
        # authz.body.challenges is a set of ChallengeBody objects.
        for i in authz.body.challenges:
            # Find the supported challenge.
            if isinstance(i.chall, challenges.HTTP01):
                return i

    raise Exception('HTTP-01 challenge was not offered by the CA server.')

@contextmanager
def challenge_server(http_01_resources):
    """Manage standalone server set up and shutdown."""

    # Setting up a fake server that binds at PORT and any address.
    address = ('', 101)
    try:
        servers = standalone.HTTP01DualNetworkedServers(address,
                                                        http_01_resources)
        # Start client standalone web server.
        servers.serve_forever()
        yield servers
    finally:
        # Shutdown client web server and unbind from PORT
        servers.shutdown_and_server_close()

def perform_http01(client_acme, challb, orderr):
    """Set up standalone webserver and perform HTTP-01 challenge."""

    response, validation = challb.response_and_validation(client_acme.net.key)
    print("chalb: {0}\n\n response: {1}\n\n validation: {2}".format(challb, response, validation))

    resource = standalone.HTTP01RequestHandler.HTTP01Resource(
        chall=challb.chall, response=response, validation=validation)

    with challenge_server({resource}):
        # Let the CA server know that we are ready for the challenge.
        client_acme.answer_challenge(challb, response)

        # Wait for challenge status and then issue a certificate.
        # It is possible to set a deadline time.
        finalized_orderr = client_acme.poll_and_finalize(orderr)

    return finalized_orderr.fullchain_pem


def createAccount(user, dir_url, email):
    acc_key = jose.JWKRSA(key=rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend()) )

    # Register account and accept TOS

    net = client.ClientNetwork(acc_key, user_agent=user)
    directory = messages.Directory.from_json(net.get(dir_url).json())
    client_acme = client.ClientV2(directory, net=net)

    #Terms of Service URL is in client_acme.directory.meta.terms_of_service
    # Registration Resource: regr
    # Creates account with contact information.
    email = (email)
    regr = client_acme.new_account(messages.NewRegistration.from_data(email=email, terms_of_service_agreed=True))
    return client_acme

def getCert(client, domain):
    # Create domain private key and CSR
    pkey_pem, csr_pem = new_csr_comp(domain)

    # Issue certificate
    orderr = client.new_order(csr_pem)

    # Select HTTP-01 within offered challenges by the CA server
    challb = select_http01_chall(orderr)

    # The certificate is ready to be used in the variable "fullchain_pem".
    fullchain_pem = perform_http01(client, challb, orderr)
    return pkey_pem, fullchain_pem


print("My ssl module")
_client = createAccount("R0b", "https://acme-v02.api.letsencrypt.org/directory", "151093rb@gmail.com")
pkey, full = getCert(_client, "r0b.dynu.net")
filePath = os.path.dirname(os.path.realpath(__file__))
with open("{0}/../Data/ssl_cert/cert.pem".format(filePath), "w") as stream:
    stream.write(full)
with open("{0}/../Data/ssl_cert/p_key.key".format(filePath), "wb") as stream:
    stream.write(pkey)

print("Get ssl.\n")
client = createAccount("username", "https://acme-v02.api.letsencrypt.org/directory", "email@domain.com")
privateKey, fullChainKey = getCert(client, "yourDomain.com")
print("Private key:\n\t{0}\n\nFullchain Key:\n\t{1}".format(privateKey, fullChainKey))