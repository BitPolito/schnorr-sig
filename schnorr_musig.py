import schnorr_lib as sl
import sys, json, getopt

def main(argv):

    try:
        opts, args = getopt.getopt(argv, "hm:", ["msg="])

    except getopt.GetoptError:
        print('[i] Command not found. Type -h for help')
        sys.exit(2)
        
    for opt, arg in opts:
        if opt == '-h':
            print('[i] Command: schnorr_musig.py -m <msg_to_sign>')
            sys.exit()
        elif opt in ("-m", "--msg"):
            msg = arg

    # Get message digest
    try: 
        M = sl.sha256(msg.encode())
    except Exception:
        print("Error, message should be defined")
        sys.exit(2)
        
    # Get keypairs
    try:
        keypairs = json.load(open("keypairs.json", "r"))
    except Exception:
        print("Error, file not specified or nonexistent")
        sys.exit(2)

    Rsum, ssum, X = sl.schnorr_musig_sign(M, keypairs)
    
    result = sl.schnorr_musig_verify(M, Rsum, ssum, X)
    print(">>> Is the sign right? (Rv equals Rsum + e'*X)?", result)

if __name__ == "__main__":
   main(sys.argv[1:])

