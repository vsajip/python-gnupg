#!/usr/bin/python3

import gnupg
import os
import argparse

gpg = gnupg.GPG()

parser = argparse.ArgumentParser(usage="%(prog)s [-h] signature [-f FILE] [-k KEYRING]\n"
                                       "Exemple: %(prog)s chemin_fichier.asc -f chemin_fichier -k chemin_clef",
                                 epilog="Les commandes peuvent être associées")
parser.add_argument('signature', type=str, help="Chemin d'accès vers le fichier de signature")
parser.add_argument('-f', '--file', type=str, help="Chemin d'accès vers le fichier qui à été signé")
parser.add_argument('-k', '--keyring', type=str, help="Chemin d'accès vers le répertoire de trouseau de clef")
parser.add_argument('-v', '--version', action='version', version="%(prog)s 1.0")

args = parser.parse_args()


def verif_sign(path_sign, path_file=None):
    '''
    :param path_sign: Fichier de signature
    :param path_file: Fichier signé (par défaut ça prend le nom du fichier de signature sans l'extension)
    :return: Information sur l'état des fichiers de signature
    '''
    if path_file is None:
        path_file, extension = os.path.splitext(path_sign)
    try:
        if os.path.isfile(path_file):
            with open(path_sign, "rb") as fs:
                verify = gpg.verify_file(fs, path_file)
                infos = verify.sigs_info
                print(f"\nNombre de signature: {len(infos)}\n")
                for key, value in infos.items():
                    print(f"Status:\t\t {value['status']}")
                    print(f"Key_id:\t\t {key}")
                    if 'timestamp' in value:
                        print(f"Creation_date:\t {value['creation_date']}")
                        print(f"Timestamp:\t {value['timestamp']}")
                    if 'username' in value:
                        print(f"Username:\t {value['username']}")
                    if 'fingerprint' in value:
                        print(f"Fingerprint:\t {value['fingerprint']}")
                    if 'trust_level' in value:
                        print(f"Trust_level:\t {value['trust_level']} | {value['trust_text']}")
                    print()
        else:
            print(f"Fichier << {path_file} >> introuvable")
    except Exception as e:
        print(e)


if __name__ == '__main__':
    try:
        gpg = gnupg.GPG(gnupghome=args.keyring)
    except ValueError as e:
        print(e)

    verif_sign(args.signature, args.file)
