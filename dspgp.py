import subprocess
import sys
from getpass import getpass

import click
import pexpect
import pgpy


@click.group()
def cli():
    pass


@click.command()
@click.option('--secret-key', '-K', required=True)
@click.option('--signature-keyid', '-F', required=True)
def create(secret_key, signature_keyid):

    with open(f'{secret_key}', 'r') as f:
        string = f.read()
        priv_key = pgpy.PGPKey()
        priv_key.parse(string)

    password = getpass('your password: ')
    try:
        with priv_key.unlock(password):
            message = pgpy.PGPMessage.new(f'{str(signature_keyid)}')
            message |= priv_key.sign(message)
            click.echo(message)
    except pgpy.errors.PGPDecryptionError as e:
        click.echo(e)
        sys.exit(1)

    with open(f'{signature_keyid}.asc', 'w') as f:
        f.write(str(message))


@click.command()
@click.option('--public-key', '-K', required=True)
@click.option('--delete-signature', '-D', required=True)
def merge(public_key, delete_signature):

    with open(f'{public_key}', 'r') as f:
        string = f.read()
        pub_key = pgpy.PGPKey()
        pub_key.parse(string)

    del_sig = pgpy.PGPMessage.from_file(delete_signature)

    try:
        if pub_key.verify(del_sig):
            del_sig_keyid = del_sig.message
    except pgpy.errors.PGPError as e:
        click.echo(e)
        sys.exit(1)

    # Delete Signature from Public Key
    pub_fingerprint = pub_key.fingerprint.replace(" ", "")
    gpg = pexpect.spawn(f"gpg --edit-key {pub_fingerprint}")
    gpg.expect("gpg>")

    # all UID
    gpg.sendline("uid *")
    gpg.expect("gpg>")

    # delsig
    gpg.sendline("delsig")

    while True:
        gpg.expect(r"(y/N/q)|gpg>")

        # all signatures are checked
        if gpg.after == b"gpg>":
            break

        if gpg.after == b"y/N/q":
            if del_sig_keyid in gpg.before.decode('UTF-8'):
                gpg.sendline("y")
            else:
                gpg.sendline("N")

    # Save
    gpg.sendline("save")

    # Export
    with open(f'deleted_{public_key}', 'w') as f:
        # cmd = f"gpg --armor --export {pub_fingerprint}"
        # subprocess.run(cmd, stdout=f)

        subprocess.run(["gpg",
                        "--armor",
                        "--export",
                        f"{pub_fingerprint}"],
                       stdout=f)
        subprocess.run(["cat", f"deleted_{public_key}"])


cli.add_command(create)
cli.add_command(merge)


if __name__ == '__main__':
    cli()
