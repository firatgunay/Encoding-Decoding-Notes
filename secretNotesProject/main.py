from tkinter import *
from tkinter import messagebox
import base64

def encode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()

def decode(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)

def save_encrypt_notes():
    title = title_entry.get()
    message = input_text.get("1.0", END)
    master_secret = master_entry.get()

    if len(title)==0 or len(message)==0 or len(master_secret)==0 :
        messagebox.showwarning(title="Error!", message="Enter all info. ")
    else:
        encrypt_message = encode(master_secret, message)
        try:
            with open("mysecret.txt","a") as data_file:
                data_file.write(f"\n{title}\n{encrypt_message}")

        except FileNotFoundError:
            with open("mysecret.txt","w") as data_file:
                data_file.write(f"\n{title}\n{message}")

        finally:
            title_entry.delete(0, END)
            master_entry.delete(0, END)
            input_text.delete("1.0", END)

def decrypt_notes():
    message_encrypted = input_text.get("1.0", END)
    master_secret = master_entry.get()

    if len(message_encrypted)==0 or len(master_secret)==0:
        messagebox.showerror(title="Error!", message="Enter all info. ")
    else:
        try:
            decrypt_message = decode(master_secret, message_encrypted)
            input_text.delete("1.0", END)
            input_text.insert("1.0", decrypt_message)
        except:
            messagebox.showerror(title="Error!", message="Enter encrypted text!")


window = Tk()
window.title("Secret Notes")
window.config(padx=20, pady=20)

FONT = ("arial", 13, "bold")

photo = PhotoImage(file="topsecret.png")
photo_label = Label(image=photo)
photo_label.pack()

title_info = Label(text= "enter your title", font=FONT)
title_info.pack()

title_entry = Entry(width=30)
title_entry.pack()

input_info = Label(text="enter your secret", font=FONT)
input_info.pack()

input_text = Text(width=40, height=10)
input_text.pack()

master_label = Label(text= "enter master key", font= FONT)
master_label.pack()

master_entry = Entry(width=30)
master_entry.pack()

save_button = Button(text= "save & encrypt", command=save_encrypt_notes)
save_button.pack()

decrypt_button = Button(text= "Decrypt", command=decrypt_notes)
decrypt_button.pack()

window.mainloop()