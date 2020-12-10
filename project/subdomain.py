import subprocess
import argparse
import threading
import queue
import time
import sys

parser = argparse.ArgumentParser(description="Subdomain Scan. Usage: python subdomain_finder.py example.com subdomain_wordlist.txt\n[*.example.com will be scanned]")
parser.add_argument("domain", help="Domain To Scan")
parser.add_argument("wordlist", help="Subdomain Wordlist")
parser.add_argument("-t", dest="threads", default=1, help="Threads [1 - 222]")
parser.add_argument("-r", dest="recursive", action="store_true", help="Recursive mode")
args = parser.parse_args()

domain = args.domain
wordlist = args.wordlist
threadsNumber = int(args.threads)
recursive = args.recursive

class ScanUtils:
    messages = queue.Queue()
    stopThreads = False
    subdomainWordlist = []
    baseWordlist = []
    recursiveWordlist = []
    threads = []
    subdomainsToScan = 0
    subdomainsScaned = 0

def exec_comand(comand):
    try:
        cmd = subprocess.Popen(comand, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out = str(cmd.stdout.read())

        return out
    except Exception as error:
        print("exec_comand " + str(error))
        exit(0)

def bruteforce(ini, end):
    for i in range(ini, end):
        subdomain = ScanUtils.subdomainWordlist[i]

        if ScanUtils.stopThreads:
            exit(0)

        try:
            comand = "host " + str(subdomain) + "." + domain
            out = str(exec_comand(comand)).replace("b'", "").replace("\\n'", "").replace("\\n", " ").replace("\n", " ") + "\n"

            if ("not found:" in out) or (out == "") or (len(out) < 4) or ("connection timed out" in out):
                ScanUtils.messages.put("progressBar")
                ScanUtils.subdomainsScaned += 1
                continue

            if domain in out:
                if recursive:
                    for s in ScanUtils.baseWordlist:
                        recursiveSubdomain = s + "." + subdomain
                        ScanUtils.recursiveWordlist.append(recursiveSubdomain)

                ScanUtils.messages.put(out)

        except KeyboardInterrupt:
            ScanUtils.stopThreads = True
            ScanUtils.messages.put("exit")
            exit(0)

        except Exception as error:
            print(subdomain + " " + str(error).replace("b'", "").replace("\\n'", "").replace("\r", "").replace("\n", " "))
            ScanUtils.messages.put("progressBar")

        ScanUtils.subdomainsScaned += 1

def readFileAndGenerateWordlist(name):
    try:
        file = open(name, "r")
        data = file.readlines()
        file.close()

        subdomains = []

        for line in data:
            line = line.replace("\n", "").replace("\r", "")

            if len(line) == 0:
                continue

            subdomains.append(line)

        if len(subdomains) > 0:
           return subdomains
        else:
            print("Wordlist has no data.")
            exit(0)

    except Exception as error:
        print("readFileAndGenerateWorlist " + str(error))
        exit(0)

def printResult():
    while True:
        if ScanUtils.stopThreads:
            exit(0)
        message = ScanUtils.messages.get()
        if message == "exit":
            exit(0)
        elif message == "progressBar":
            sys.stdout.flush()
            progressBar()
        else:
            print(message)
            sys.stdout.flush()
            progressBar()

def startThreads():
    for thread in ScanUtils.threads:
        thread.start()
    try:
        while True:
            threadCount = threading.active_count()

            if threadCount < 3:
                ScanUtils.stopThreads = True
                ScanUtils.messages.put("exit")
                if recursive and (len(ScanUtils.recursiveWordlist) > 0):
                    startRecursiveLoop()
                    return

                exit(0)

            time.sleep(1.111)
    except KeyboardInterrupt:
        print("[*] Stopping Threads ...")
        ScanUtils.stopThreads = True
        ScanUtils.messages.put("exit")
        exit(0)

def progressBar():
    sys.stdout.flush()
    sys.stdout.write("[")
    sys.stdout.write(str(ScanUtils.subdomainsScaned) + "/" + str(ScanUtils.subdomainsToScan))
    sys.stdout.write("]\r")


def createThreads():
    subdomains = ScanUtils.subdomainWordlist
    try:
        wordlistLenght = len(subdomains)
        ScanUtils.subdomainsToScan += wordlistLenght

        if threadsNumber > wordlistLenght:
            print("Too many threads for this wordlist")
            exit(0)

        if (threadsNumber < 1) or (threadsNumber > 222):
            print("Invalid Threads, choose between 1 to 222")

        printThread = threading.Thread(target=printResult)
        ScanUtils.threads.append(printThread)

        if threadsNumber == 1:
            thread = threading.Thread(target=bruteforce, args=[0, wordlistLenght])
            ScanUtils.threads.append(thread)

        else:
            dWordlist = int(wordlistLenght/threadsNumber)
            ini = 0
            end = dWordlist

            thread = threading.Thread(target=bruteforce, args=[ini, end])
            ScanUtils.threads.append(thread)

            for i in range(1, threadsNumber-1):
                ini = ini + dWordlist
                end = end + dWordlist

                thread = threading.Thread(target=bruteforce, args=[ini, end])
                ScanUtils.threads.append(thread)

            if end < wordlistLenght:
                finalThreadToRun = threading.Thread(target=bruteforce, args=[end, wordlistLenght])
                ScanUtils.threads.append(finalThreadToRun)

    except Exception as error:
        print("createThreads " + str(error))
        exit(0)

def startRecursiveLoop():
    try:
        ScanUtils.subdomainWordlist = ScanUtils.recursiveWordlist
        ScanUtils.recursiveWordlist = []
        ScanUtils.stopThreads = False
        ScanUtils.threads = []

        try:
            while True:
                threadCount = threading.active_count()
                if threadCount == 1:
                    break
                time.sleep(0.4)
        except KeyboardInterrupt:
            exit(0)
        createThreads()
        startThreads()
    except Exception as error:
        print("startRecursiveLoop " + str(error))
        exit(0)

def main():
    try:
        ScanUtils.subdomainWordlist = readFileAndGenerateWordlist(wordlist)
        ScanUtils.baseWordlist = ScanUtils.subdomainWordlist
        createThreads()

        print("[*] Scanning *." + domain + "\n")
        startThreads()
    except Exception as error:
        print("main " + str(error))


main()
