import os
import sys


#program starts with main function
def main():
    
    try:    #check binary file
        inputFile = sys.argv[1] #argv[1] is input file, argv[0] is the python code
    except:
        print("Binary file not found")  
        sys.exit(0) #if doesn't exist, abort

    fileName = '.output' #inputFile text
    analysF = '.code'    #code analyzed
    
    os.system("objdump -d -M intel " + inputFile + " > " + fileName) #disassemble binary file    
    
    print ('\t\t pyDFC - Design flaws Catcher')
    print ('A searching tool to find design flaws and vulnerable functions in C binary code\n ')    
    
    #seleziona solamente la parte di codice necessaria a seconda del sistema operativo di compilazione
    #if "pei-i386" in fileName:
    #   print("Windows binary detected")
    #   osType = "windows"
    #   os.system(" cat -n " + fileName + " | sed -n '/___gcc_deregister_frame/,/<___dyn_tls_dtor/p' > " + analysF)
    #elif "elf64-x86-64" in fileName:
    #    print("Linux binary detected")
    #    osType = "linux"        
    #    
    os.system(" cat -n " + fileName + " | sed -n '/<register_tm_clones>/,/__libc_csu_init/p' > " + analysF)    
    
    openFile = open(analysF, "r")
    
    text = openFile.read()    
    
    while 1: 
        print("Select input for ")
        print("\t1) Search design flaws ")
        print("\t2) Find gadgets [beta]")
        print("\t3) Print disassembled code ")
        print("\t4) Search by line or address ")
        print("\t5) Find stack canaries ")
    
        try:
            slct = eval(input('Your option: '))
        
            if slct == 1 :
                #findDF(analysF, osType)
                findDFlinux(analysF)
            elif slct == 2:
                findGadgets(analysF)
            elif slct == 3:
                printFullOBJ(text, inputFile)
            elif slct == 4:
                searchLine(analysF)
            elif slct == 5:
                findCanary(analysF)
            else :
                print("Exit from DFC")
                sys.exit(0)
        except:  #nel caso non si stato inserito un intero, esce
             print("Exit from DFC")
             sys.exit(0)



#print full assembly binary code, beta
def printFullOBJ(text, inputFile):
    print("\n")    
    print (text)
    print("\n")
    
    print("Do you want to save this text? y/n")
    ans = input()
    
    if ans == 'y':
        os.system("objdump -d -M intel " + inputFile + " > printed_binary.txt")
    elif ans == 'n':
        return
    else:
        return


#helps to find gadgets, in beta
def findGadgets(file):
    print("\n")
    
    print("\n\t pop pop ret:")
    os.system("egrep -A2 'pop' < " + file)

    
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
    
# function finder design flaws in linux binary code
def findDFlinux(file):

    print("\n")
    print("Design flaws in code:")


    print("\t Possible unformatted printf:")
    os.system("egrep '<printf' < " + file + " | wc -l")  #number of matches
    os.system("egrep '<printf' < " + file)  #debug printf

    print("\n\t gets:")
    os.system("egrep '<gets' < " + file + " | wc -l") 
    os.system("egrep '<gets' < " + file)   #debuf fgets

    print("\n\t Possible unsecure scanf:")
    os.system("egrep 'scanf' < " + file + " | wc -l")
    os.system("egrep 'scanf' < " + file)   #debug scanf

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
        
        
# function finder design flaws in binary code
def findDF(file, osType):

    print("\n")
    print("Design flaws in code:")

    if osType == "linux":
        print("\t Possible unformatted printf:")
        os.system("egrep '<printf@' < " + file + " | wc -l")  #number of matches
        os.system("egrep '<printf@' < " + file)  #debug printf
    
        print("\n\t gets:")
        os.system("egrep '<gets@' < " + file + " | wc -l") 
        os.system("egrep '<gets@' < " + file)   #debuf fgets
    
        print("\n\t Possible unsecure scanf:")
        os.system("egrep 'scanf@' < " + file + " | wc -l")
        os.system("egrep 'scanf@' < " + file)   #debug scanf
    
        print("\n\t strcpy:")
        os.system("egrep '<strcpy@' < " + file + " | wc -l")
        os.system("egrep '<strcpy@' < " + file)
        
        print("\n\t strcat:")
        os.system("egrep '<strcat@' < " + file + " | wc -l")
        os.system("egrep '<strcat@' < " + file)
        
        print("\n\t strncpy:")
        os.system("egrep '<strncpy@' < " + file + " | wc -l")
        os.system("egrep '<strncpy@' < " + file)    
        
        print("\n\t strncat:")
        os.system("egrep '<strncat@' < " + file + " | wc -l")
        os.system("egrep '<strncat@' < " + file)
    
        print("\n\t sprintf:")
        os.system("egrep '<sprintf@' < " + file + " | wc -l")
        os.system("egrep '<sprintf@' < " + file)
    
        print("\n\t vsprintf:")
        os.system("egrep '<vsprintf@' < " + file + " | wc -l")
        os.system("egrep '<vsprintf@' < " + file)

    elif osType == "windows":
        print("\t Possible unformatted printf:")
        os.system("egrep '<_printf' < " + file + " | wc -l")  #number of matches
        os.system("egrep '<_printf' < " + file)  #debug printf
    
        print("\n\t gets:")
        os.system("egrep '<_gets' < " + file + " | wc -l") 
        os.system("egrep '<_gets' < " + file)   #debuf fgets
    
        print("\n\t Possible unsecure scanf:")
        os.system("egrep '_scanf' < " + file + " | wc -l")
        os.system("egrep '_scanf' < " + file)   #debug scanf
    
        print("\n\t strcpy:")
        os.system("egrep '<_strcpy' < " + file + " | wc -l")
        os.system("egrep '<_strcpy' < " + file)
        
        print("\n\t strcat:")
        os.system("egrep '<_strcat' < " + file + " | wc -l")
        os.system("egrep '<_strcat' < " + file)
        
        print("\n\t strncpy:")
        os.system("egrep '<_strncpy' < " + file + " | wc -l")
        os.system("egrep '<_strncpy' < " + file)    
        
        print("\n\t strncat:")
        os.system("egrep '<_strncat' < " + file + " | wc -l")
        os.system("egrep '<_strncat' < " + file)
    
        print("\n\t sprintf:")
        os.system("egrep '<_sprintf' < " + file + " | wc -l")
        os.system("egrep '<_sprintf' < " + file)
    
        print("\n\t vsprintf:")
        os.system("egrep '<_vsprintf' < " + file + " | wc -l")
        os.system("egrep '<_vsprintf' < " + file)
        
    else: 
        print("Unknown file format")

    print("\n")



main()



