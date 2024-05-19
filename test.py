import gradio as gr
import os
import algo.AES as AES

methods = ["SHA224", "SHA256", "SHA384", "SHA512"]

def encrypt(file, method, password=None, keyfile=None):
	output = os.path.join(os.path.dirname(__file__), "output", os.path.basename(file))
	key = AES.KeyMix(password, keyfile)
	print(key)
	return AES.encrypt(file, key, output, method)
	
def decrypt(file, method, password=None, keyfile=None):
	output = os.path.join(os.path.dirname(__file__), "output", os.path.basename(file))
	key = AES.KeyMinx(password, keyfile)
	print(key)
	return AES.decrypt(file, key, output, method)
	
def password_check(file, method, password, confirm_password, keyfile=None):
	if password == confirm_password:
		password = AES.KeyMix(password, keyfile)
		return encrypt