import gradio as gr
import os
import subprocess

import algo.AES as AES

methods = ["SHA224", "SHA256", "SHA384", "SHA512"]

def encrypt(files, method, password=None, confirm_password=None, keyfile=None):
    if password == confirm_password:
        pass
    else:
        raise ValueError("Passwords do not match.")
    key = AES.KeyMix(password, keyfile)
    flags = {}
    print(files)
    for file in files:
        output_path = os.path.join(os.path.dirname(__file__), "output", os.path.basename(file))
        flags[file] = AES.encrypt(file, key, output_path, method)
    if all(flags.values()):
        raise ValueError("Encryption completed successfully")
    else:
        raise ValueError("Encryption failed")

def decrypt(files, method, password=None, keyfile=None):
    key = AES.KeyMix(password, keyfile)
    flags = {}
    for file in files:
        output_path = os.path.join(os.path.dirname(__file__), "output")
        flags[file] = AES.decrypt(file, key, output_path, method)
    if all(flags.values()):
        raise ValueError("Decryption completed successfully")
    else:
        raise ValueError("Decryption failed")
    
with gr.Blocks() as demo:
    gr.Markdown("# An Apllication for Encryption and Decryption of Files")
    with gr.Tab("Encrypt"):
        with gr.Column():
            files = gr.Files(type="filepath", label="Select a file to encrypt")
            method = gr.Radio(methods, label="Select an encryption method")
            gr.Markdown("## Password or/and Key File")
            gr.Markdown("Choose either a password or a key file to encrypt/decrypt the file.")
            password = gr.Textbox(type="password", label="Enter a password")
            confirm_password = gr.Textbox(type="password", label="Confirm password")
            keyfile = gr.File(type="filepath", label="Select a key file")
            
        with gr.Row():
            encrypt_button = gr.Button("Encrypt")
            encrypt_button.click(encrypt, inputs=[files, method, password, confirm_password, keyfile])
            open_button = gr.Button("Open Output Folder")
            open_button.click(lambda: os.startfile(os.path.join(os.path.dirname(__file__), "output")))
            
    with gr.Tab("Decrypt"):
        with gr.Column():
            files = gr.Files(type="filepath", label="Select a file to decrypt", file_types=[".enc"])
            method = gr.Radio(methods, label="Select an decryption method")
            gr.Markdown("## Password or/and Key File")
            gr.Markdown("Choose either a password or a key file to encrypt/decrypt the file.")
            password = gr.Textbox(type="password", label="Enter a password")
            keyfile = gr.File(type="filepath", label="Select a key file")
        
        with gr.Row():
            decrypt_button = gr.Button("Decrypt")
            decrypt_button.click(decrypt, inputs=[files, method, password, keyfile])
            open_button = gr.Button("Open Output Folder")
            open_button.click(lambda: os.startfile(os.path.join(os.path.dirname(__file__), "output")))

if __name__ == "__main__":
    bat_file = __file__.replace("app.py", "browser.bat")
    subprocess.call([bat_file], shell=True)
    demo.launch()