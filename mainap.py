import io
from flask import Flask, render_template, request, send_file, flash, redirect, url_for
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
import base64
import tempfile

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret-key'

#the below code is for the aes encryption
def encrypt_image(key, image_bytes):
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted_bytes = cipher.encrypt(pad(image_bytes, AES.block_size))
    encrypted_image = base64.b64encode(encrypted_bytes).decode('utf-8')
    return encrypted_image

def decrypt_image(key, encrypted_image):
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted_bytes = unpad(cipher.decrypt(encrypted_image), AES.block_size)
    return decrypted_bytes

def generate_aes_key(passphrase):
    salt = b'salt'  # Change this value to a unique value for each user
    key = PBKDF2(passphrase, salt, dkLen=32, count=100000)
    return key

@app.route('/')
def home():
    return render_template('home.html')

#Error handling
# @app.errorhandler(400)
# def bad_request_error(e):
#     flash('Bad Request: The request could not be understood by the server.')
#     return redirect(url_for('home'))

# # The following function registers a custom error handler for 404 Not Found errors.
# @app.errorhandler(404)
# def not_found_error(e):
#     flash('Page Not Found: The requested page does not exist.')
#     return redirect(url_for('home'))

# # The following function registers a custom error handler for general server errors.
# @app.errorhandler(500)
# def internal_server_error(e):
#     flash('Internal Server Error: An error occurred on the server.')
#     return redirect(url_for('home'))



#the below code generates the RSA public and Private keys

@app.route('/generate_rsa_keys', methods=['GET', 'POST'])
def generate_rsa_keys():
    if request.method == 'POST':
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()

        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        return render_template(
            'rsa_keys.html',
            private_key=private_key_pem.decode('utf-8'),
            public_key=public_key_pem.decode('utf-8')
        )

    return render_template('generate_rsa_keys.html')

# The below code calls the required encryptions

@app.route('/encrypt', methods=['GET', 'POST'])
def encrypt():
    if request.method == 'POST':
        algorithm = request.form['algorithm']
        if algorithm == 'aes':
            passphrase = request.form['passphrase']
            image = request.files['image']
            if not image:
                flash('No image file selected.')
                return redirect(url_for('encrypt'))
            image_bytes = image.read()
            key = generate_aes_key(passphrase)
            # encrypted_bytes = encrypt_image(key, image_bytes)
            try:
                encrypted_bytes = encrypt_image(key, image_bytes)
            except Exception as e:
                flash('Encryption failed: {}'.format(str(e)))
                return redirect(url_for('encrypt'))
            extension = image.filename.rsplit('.', 1)[-1].lower()
            encrypted_file = io.BytesIO(base64.b64decode(encrypted_bytes))
            return send_file(
                encrypted_file,
                mimetype='application/octet-stream',
                download_name='encrypted_image.bin',            # encrypted_bytes = encrypt_image(key, image_bytes)

                as_attachment=True
            )
        elif algorithm == 'hybrid':
            rsa_public_key = request.form['rsa_public_key']
            passphrase = request.form['passphrase']
            image = request.files['image']
            image_bytes = image.read()

            # Generate AES key
            aes_key = generate_aes_key(passphrase)
            print(aes_key)
            # Encrypt image using AES
            try:
                encrypted_bytes = encrypt_image(aes_key, image_bytes)
            except Exception as e:
                flash('hybrid encryption failed: {}'.format(str(e)))
                return redirect(url_for('encrypt'))
            # Encrypt AES key using RSA public key
            public_key = serialization.load_pem_public_key(
                rsa_public_key.encode(),
                backend=default_backend()
            )
            encrypted_aes_key = public_key.encrypt(
                aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return render_template('success.html', aes_key=base64.b64encode(encrypted_aes_key).decode('utf-8'), encrypted_image=encrypted_bytes)

        else:
            # Handle invalid algorithm selection
            return ("Invalid algorithm selected."+algorithm)

        # Common code for both algorithms
        # Return the encrypted image or perform further actions
        return render_template('encrypt.html')

    return render_template('encrypt.html')

#The below code consists all the decryption logic

@app.route('/decrypt', methods=['GET', 'POST'])
def decrypt():
    if request.method == 'POST':
        algorithm = request.form['algorithm']
        if algorithm == 'aes':
            passphrase = request.form['passphrase']
            encrypted_image = request.files['encrypted_image']
            encrypted_bytes = encrypted_image.read()
            key = generate_aes_key(passphrase)
            
            try:
                decrypted_bytes = decrypt_image(key, encrypted_bytes)
            except Exception as e:
                flash('Decryption failed: {}'.format(str(e)))
                return redirect(url_for('decrypt'))
            
            return send_file(
                io.BytesIO(decrypted_bytes),
                mimetype='application/octet-stream',
                download_name='decrypted_image.jpg',  # Update the filename and extension as needed
                as_attachment=True
            )
        elif algorithm == 'hybrid':
            rsa_private_key = request.form['rsa_private_key']
            encrypted_aes_key = request.form['encrypted_aes_key']
            encrypted_image = request.files['encrypted_image']

            # Convert the encrypted image string back to
            encrypted_image_bytes = encrypted_image.read()

            # Decrypt AES key using RSA private key
            private_key = serialization.load_pem_private_key(
                rsa_private_key.encode(),
                password=None,
                backend=default_backend()
            )
            decrypted_aes_key = private_key.decrypt(
                base64.b64decode(encrypted_aes_key.encode()),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            print(decrypted_aes_key)
            # Decrypt image using AES
            # decrypted_image_bytes = decrypt_image(decrypted_aes_key, encrypted_image_bytes)
            
            decrypted_image_bytes = decrypt_image(decrypted_aes_key, encrypted_image_bytes)
            

            return send_file(
                io.BytesIO(decrypted_image_bytes),
                mimetype='image/jpeg',
                download_name='decrypted_image.jpg',
                as_attachment=True
            )
        else:
            # Handle invalid algorithm selection
            return "Invalid algorithm selected."

        # Common code for both algorithms if any

    return render_template('decrypt.html')

#The below code is a strech , it is for downloading the hybrid encrypted image

@app.route('/download_encrypted_image', methods=['POST'])
def download_encrypted_image():
    encrypted_aes_key = request.form['encrypted_aes_key']
    encrypted_image = request.form['encrypted_image']

    encrypted_file = io.BytesIO(base64.b64decode(encrypted_image))
    return send_file(
        encrypted_file,
        mimetype='application/octet-stream',
        download_name='encrypted_image.bin',
        as_attachment=True
    )


if __name__ == '__main__':
    app.run()

