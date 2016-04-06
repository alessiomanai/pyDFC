import os
import sys


#
def main():
    
    inputFile = sys.argv[1] #argv[1] is input file, argv[0] is the python code

    fileName = '.output'
    
    analysF = '.code'    
    
    os.system("objdump -d -M intel " + inputFile + " > " + fileName) #disassemble binary file
    
    #seleziona solamente la parte di codice necessaria
    os.system(" cat -n " + fileName + " | sed -n '/<register_tm_clones>/,/__libc_csu_init/p' > " + analysF)    
    
    openFile = open(analysF, "r")
    
    text = openFile.read()    

    #os.remove(fileName) #remove red file
    
    print ('\t\t pyDFC - Design flaws Catcher')
    print ('A searching tool to find design flaws and vulnerable functions in C binary code\n ')


    while 1: 
        print("Select input for ")
        print("\t1) Search design flaws ")
        print("\t2) Find gadgets [beta]")
        print("\t3) Print disassembled code ")
        print("\t4) Search by line or address ")
        print("\t5) Find stack canaries ")
    
        slct = eval(input('Your option: '))
    
        if slct == 1 :
            findDF(analysF)
        elif slct == 2:
            findGadgets(analysF)
        elif slct == 3:
            printFullOBJ(text)
        elif slct == 4:
            searchLine(analysF)
        elif slct == 5:
            findCanary(analysF)
        else :
            sys.exit(0)



#print full assembly binary code, beta
def printFullOBJ(text):
    print("\n")    
    print (text)
    print("\n")


#helps to find gadgets, in beta
def findGadgets(file):
    print("\n")
    
    print("\n\t pop pop ret:")
    os.system("egrep -A2 'pop' < " + file)
    
    #print("\n\t pop pop ret:")
    #os.system("egrep -A1 'mov' < " + file)
    
    print("\n")


#simple searching with grep
def searchLine(file):
    
    print(" ")

    thing = input('Write line or address: ')
    outputLines = input('Number of lines : ')
    
    os.system("egrep -A" + outputLines + " ' " + thing + "' < " + file)    #cerca le cinque linee successive
    
    print("\n")
    
    
def findCanary(file):
    
    print("\n\t Stack canaries:")
    os.system("egrep '(fs)|(gs):' < " + file + " | wc -l")
    os.system("egrep -A3 '(fs)|(gs):' < " + file)   #debug scanf
    print("\n")
    

# function finder design flaws in binary code
def findDF(file):

    print("\n")
    print("Design flaws in code:")

    print("\t Possible unformatted printf:")
    os.system("egrep '<printf@' < " + file + " | wc -l")  #number of matches
    os.system("egrep '<printf@' < " + file)  #debug printf

    print("\n\t gets:")
    os.system("egrep '<gets' < " + file + " | wc -l") 
    os.system("egrep '<gets' < " + file)   #debuf fgets

    print("\n\t unsecure scanf:")
    os.system("egrep '<scanf' < " + file + " | wc -l")
    os.system("egrep '<scanf' < " + file)   #debug scanf

    print("\n\t strcpy:")
    os.system("egrep '<strcpy' < " + file + " | wc -l")
    os.system("egrep '<strcpy' < " + file)
    
    print("\n\t strcat:")
    os.system("egrep '<strcat' < " + file + " | wc -l")
    os.system("egrep '<strcat' < " + file)
    
    print("\n\t strncpy:")
    os.system("egrep '<strncpy' < " + file + " | wc -l")
    os.system("egrep '<strncpy' < " + file)    
    
    print("\n\t strncat:")
    os.system("egrep '<strncat' < " + file + " | wc -l")
    os.system("egrep '<strncat' < " + file)

    print("\n\t sprintf:")
    os.system("egrep '<sprintf' < " + file + " | wc -l")
    os.system("egrep '<sprintf' < " + file)

    print("\n\t vsprintf:")
    os.system("egrep '<vsprintf' < " + file + " | wc -l")
    os.system("egrep '<vsprintf' < " + file)

    print("\n")


main()



