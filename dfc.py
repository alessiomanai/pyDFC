import os
import sys


#
def main():
    
    inputFile = sys.argv[1] #argv[1] is input file, argv[0] is the python code

    fileName = '.output'
    
    analysF = '.code'    
    
    os.system("objdump -d -M intel " + inputFile + " > " + fileName) #disassemble binary file
    
    os.system(" cat -n " + fileName + " | sed -n '/<main>/,/__libc_csu_init/p' > " + analysF)    
    
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
    
        slct = eval(input('Your option: '))
    
        if slct == 1 :
            findDF(analysF)
        elif slct == 2:
            findGadgets(analysF)
        elif slct == 3:
            printFullOBJ(text)
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
    
    os.system("egrep 'call' < " + file)
    os.system("egrep 'jmp' < " + file)
    os.system("egrep 'pop' < " + file)
    os.system("egrep 'ret' < " + file)
    
    

# function finder design flaws in binary code
def findDF(file):

    nFlaws = 0

    print("\n")
    print("Design flaws in code:")

    if os.system("egrep 'printf' < " + file) :  #debug printf
        nFlaws = 1

    if os.system("egrep 'fgets' < " + file) :  #debuf fgets
        nFlaws = 1
    
    if os.system("egrep 'scanf' < " + file):   #debug scanf
        nFlaws = 1

    if os.system("egrep '%fs' < " + file):   #debug scanf
        nFlaws = 1
        
    if nFlaws == 0:     #se non trova falle
        print("No flaws found")

    print("\n")


main()



