key='b85Axk4PYXoYcAwkpTBI6mr7mYDIKG6Q'

from base64 import b64decode
from base64 import b64encode
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from pythonping import ping
from tkinter import *  
from tkinter import messagebox 
from tkinter import scrolledtext
from tkinter.ttk import Progressbar
import codecs
import hashlib
import hmac
import os
import re
import select
import socket
import sys
import subprocess
import time

profilearr=[]

HASH_ALGO = hashlib.sha256
def loadprofiles():
	global profile,profilearr
	profile.delete(0,END)
	files = os.listdir('./')
	cnt=0;
	for i in range(len(files)):
		content=''
		with open(files[i], 'r') as fp:
			content = fp.read()
		dec=decrypt(content)
		if(dec!=False):
			profilename=profileid=''
			for line in dec.splitlines():
				cmd,param=line.split(':',1)
				if(cmd=='profileid'):
					profileid=param
				if(cmd=='profilename'):
					profilename=param
		if(profilename!='' and profileid!=''):
			profile.insert(cnt, profilename)
			profilearr.insert(cnt,profileid)
			cnt+=1
	profile.update()
	window.update()
def decrypt(ciphertext):
	global key
	if(ciphertext==''):
		messagebox.showinfo('Error','Connection key invalid(1)')
		return False
	ciphertext=bytes(ciphertext, 'utf-8')
	try:
		c=b64decode(ciphertext)
	except Exception:
		messagebox.showinfo('Error','Connection key invalid(2)')
		return False

	if(len(c)<96):
		messagebox.showinfo('Error','Connection key invalid(3)')
		return False

	iv=c[0:16]
	hmac_recieved=b64encode(c[16:16+32])
	ciphertext=c[48:len(c)]
	try:
		obj2 = AES.new(key, AES.MODE_CBC, iv)
	except Exception:
		messagebox.showinfo('Error','Connection key invalid(4)')
		return False
	hmac_valid=b64encode(hmac.new(key, ciphertext, HASH_ALGO).digest())
	if(hmac_valid!=hmac_recieved):
		messagebox.showinfo('Error','Connection key invalid(5)')
		return False
	plaintext = obj2.decrypt(ciphertext)
	plaintext = unpad(plaintext, AES.block_size)
	return plaintext.decode("utf-8")
def paste():
	global txt,window
	cliptext = window.clipboard_get()
	cliptext = re.sub(r"\s+", '', cliptext)
	plaintext=decrypt(cliptext)
	
	if(plaintext!=False):
		for line in plaintext.splitlines():
			cmd,param=line.split(':',1)
			if(cmd=='profileid'):
				file = codecs.open(param+".txt", "w", "utf-8")
				file.write(cliptext)
				file.close()
				messagebox.showinfo('Success','Connection key installed successfull!')
		loadprofiles()
def knock(address_family,ip_address,port,type):
	if type == 'tcp':
		use_udp = False
	elif type == 'udp':
		use_udp = True
	elif type=='ping':
		response_list = ping(ip_address, size=port, count=1)
		return True
	else:
		print('err, tcp/upd/ping only')
	s = socket.socket(address_family, socket.SOCK_DGRAM if use_udp else socket.SOCK_STREAM)
	s.setblocking(False)
	socket_address = (ip_address, int(port))
	if use_udp:
		s.sendto(b'', socket_address)
	else:
		s.connect_ex(socket_address)
	s.close
	return True

def connect():
	global profile,profilearr,savebtn,bar,window
	savebtn.configure(state="disabled",text='Connecting...')
	fn=profilearr[profile.curselection()[0]]+'.txt'
	with open(fn, 'r') as fp:
		content = fp.read()
	dec=decrypt(content)
	all=dec.splitlines()
	current=1
	window.update()
	for line in all:
		bar.configure(value=round(current/len(all)*100))
		window.update()
		current+=1
		cmd,param=line.split(':',1)
		time.sleep(1)
		if(cmd=='host'):
			host=param
			address_family, _, _, _, ip = socket.getaddrinfo(host=host,port=None,flags=socket.AI_ADDRCONFIG)[0]
			ip_address = ip[0]
		if(cmd=='tcp'):
			knock(address_family,ip_address,int(param),'tcp')
		if(cmd=='udp'):
			knock(address_family,ip_address,int(param),'udp')
		if(cmd=='ping'):
			knock(address_family,ip_address,int(param),'ping')
		if(cmd=='sleep'):
			time.sleep(int(param))
		if(cmd=='mstsc'):
			subprocess.Popen("mstsc.exe "+param)
	savebtn.configure(state="normal",text='Connect')
	
key=bytes(key, 'utf-8')
if not os.path.isdir(os.getenv('LocalAppData')+'\GoodEvening'):
    os.mkdir(os.getenv('LocalAppData')+'\GoodEvening')
os.chdir(os.getenv('LocalAppData')+'\GoodEvening')


window = Tk()
window.title("Good Evening")
window.resizable(False, False)

profile = Listbox(window,width=40)
loadprofiles()
profile.select_set(0)

scrollbar = Scrollbar(window, orient="vertical")
scrollbar.config(command=profile.yview)

profile.grid(column=0, row=1,columnspan=3)

pstbtn = Button(window, text="Paste connection key", command=paste) 
pstbtn.grid(column=1, row=0)  

bar = Progressbar(window, length=200, style='black.Horizontal.TProgressbar')  
bar['value'] =0  
bar.grid(column=1, row=2)

savebtn = Button(window, text="Connect", command=connect)
savebtn.grid(column=1, row=3)  
savebtn.focus_set()

window.mainloop()