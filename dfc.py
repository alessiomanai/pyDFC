import os
import sys


#
def main():
    
    inputFile = sys.argv[1] #argv[1] is input file, argv[0] is the python code

    fileName = '.output'
    
    analysF = '.code'    
    
    os.system("objdump -d -M intel " + inputFile + " > " + fileName) #disassemble binary file
    
    os.system(" cat -n " + fileName + " | sed -n '/<register_tm_clones>/,/__libc_csu_init/p' > " + analysF)    
    
    openFile = open(analysF, "r")
    
    text = openFile.read()    

    #os.remove(fileName) #remove red file
    
    print ('\t\t pyDFC - Design flaws Catcher')
    print ('A searching tool to find design flaws and vulnerable functions in C binary code\n ')


    while 1: 
        print("Select input for ")
        print("\t1) Search design flaws ")
        print("\t2) Find gadgets ")
        print("\t3) Print disassembled code ")
        print("\t4) Search by line or address ")
    
        slct = eval(input('Your option: '))
    
        if slct == 1 :
            findDF(analysF)
        elif slct == 2:
            findGadgets(analysF)
        elif slct == 3:
            printFullOBJ(text)
        elif slct == 4:
            searchLine(analysF)
        elif slct == 0:
            sys.exit(0) #chiude il programma
        else :
            sys.exit(0)



#print full assembly binary code
def printFullOBJ(text):
    print("\n")    
    print (text)
    print("\n")


def findGadgets(file):
    print("\n")
    os.system("egrep 'call' < " + file)
    os.system("egrep 'jmp' < " + file)
    os.system("egrep 'pop' < " + file)
    os.system("egrep 'ret' < " + file)
    print("\n")

def searchLine(file):
    
    print("\n")

    thing = input('Write line or address: ')
    
    os.system("egrep -A5 ' " + thing + "' < " + file)    #cerca le cinque linee successive
    
    print("\n")
    
    


    

# function finder design flaws in binary code
def findDF(file):

    print("\n")
    print("Design flaws in code:")

    print("\t Possible unformatted printf:")
    os.system("egrep '<printf@' < " + file)  #debug printf

    print("\t gets:")
    os.system("egrep '<gets' < " + file)   #debuf fgets

    print("\t unsecure scanf:")
    os.system("egrep '<scanf' < " + file)   #debug scanf

    print("\t strcpy:")
    os.system("egrep '<strcpy' < " + file)
    
    print("\t getchar:")
    os.system("egrep '<getchar' < " + file)
    
    print("\t strcmp:")
    os.system("egrep '<strcmp' < " + file)

    print("\t Stack canaries:")
    os.system("egrep 'fs:' < " + file)   #debug scanf

    print("\n")


main()



