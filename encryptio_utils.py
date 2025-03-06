import pandas as pd
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os
import io

def password_to_key(password):
    """
    Converte una password in una chiave Fernet valida usando un salt predefinito.
    Simile all'approccio SSH, utilizza la password come unico input.
    
    Args:
        password: Password o frase scelta dall'utente (string)
        
    Returns:
        Chiave Fernet derivata dalla password
    """
    # Utilizziamo un salt fisso (non ideale per la sicurezza, ma pratico)
    # Nella realtà SSH usa una combinazione di elementi come input, ma
    # qui semplichiamo usando un salt costante
    salt = b'ExcelCryptoFixedSalt'  # Salt fisso
    
    # Deriva una chiave dalla password usando PBKDF2
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    
    # Derivazione della chiave dalla password
    key_bytes = kdf.derive(password.encode('utf-8'))
    
    # Converti in formato Fernet (base64 URL-safe)
    key = base64.urlsafe_b64encode(key_bytes)
    
    return key

def encrypt_cell_value(value, cipher):
    """Cripta un valore di cella singolo"""
    if value is None or pd.isna(value):
        return value
    
    # Converti il valore in stringa
    value_str = str(value)
    # Cripta il valore
    encrypted_bytes = cipher.encrypt(value_str.encode())
    # Converti in base64 per la leggibilità
    return base64.b64encode(encrypted_bytes).decode('utf-8')

def decrypt_cell_value(value, cipher):
    """Decripta un valore di cella singolo"""
    if value is None or pd.isna(value):
        return value
    
    try:
        # Converti da base64
        encrypted_bytes = base64.b64decode(value.encode('utf-8'))
        # Decripta il valore
        decrypted_bytes = cipher.decrypt(encrypted_bytes)
        # Converti in stringa
        decrypted_str = decrypted_bytes.decode('utf-8')
        
        # Tenta di convertire numeri in float o int
        try:
            if '.' in decrypted_str:
                return float(decrypted_str)
            else:
                try:
                    return int(decrypted_str)
                except ValueError:
                    return decrypted_str
        except ValueError:
            return decrypted_str
    except Exception as e:
        print(f"Errore durante la decrittazione: {e}")
        return f"ERRORE: {value}"

def encrypt_dataframe(df, password):
    """
    Cripta tutti i valori in un DataFrame usando una password.
    
    Args:
        df: DataFrame da criptare
        password: Password o frase scelta dall'utente
    
    Returns:
        DataFrame criptato
    """
    # Converti la password in una chiave Fernet
    key = password_to_key(password)
    
    # Crea l'oggetto di crittografia
    cipher = Fernet(key)
    
    # Crea una copia del DataFrame
    encrypted_df = df.copy()
    
    # Cripta ogni valore in ogni colonna
    for col in encrypted_df.columns:
        encrypted_df[col] = encrypted_df[col].apply(lambda x: encrypt_cell_value(x, cipher))
    
    return encrypted_df

def decrypt_dataframe(encrypted_df, password):
    """
    Decripta un DataFrame criptato usando una password.
    
    Args:
        encrypted_df: DataFrame criptato
        password: Password o frase scelta dall'utente
    
    Returns:
        DataFrame decriptato
    """
    # Converti la password in una chiave Fernet
    key = password_to_key(password)
    
    # Crea l'oggetto di crittografia
    cipher = Fernet(key)
    
    # Crea una copia del DataFrame
    decrypted_df = encrypted_df.copy()
    
    # Decripta ogni valore in ogni colonna
    for col in decrypted_df.columns:
        decrypted_df[col] = decrypted_df[col].apply(lambda x: decrypt_cell_value(x, cipher))
    
    return decrypted_df

def encrypt_excel_file(input_file, output_file=None, password=None):
    """
    Cripta i dati in un file Excel usando una password.
    
    Args:
        input_file: Percorso del file Excel da criptare
        output_file: Percorso dove salvare il file criptato (opzionale)
        password: Password o frase scelta dall'utente
    """
    # Verifica che sia stata fornita una password
    if not password:
        raise ValueError("È necessario fornire una password per la crittografia")
    
    # Determina il nome del file di output se non specificato
    if output_file is None:
        base_name = os.path.splitext(input_file)[0]
        output_file = f"{base_name}_encrypted.xlsx"
    
    # Carica il file Excel
    df = pd.read_excel(input_file)
    
    # Cripta il DataFrame
    encrypted_df = encrypt_dataframe(df, password)
    
    # Salva il DataFrame criptato
    encrypted_df.to_excel(output_file, index=False)
    
    print(f"File criptato salvato in {output_file}")

def decrypt_excel_file(input_file, output_file=None, password=None):
    """
    Decripta un file Excel criptato usando una password.
    
    Args:
        input_file: Percorso del file Excel criptato
        output_file: Percorso dove salvare il file decriptato (opzionale)
        password: Password o frase scelta dall'utente
    
    Returns:
        DataFrame decriptato
    """
    # Verifica che sia stata fornita una password
    if not password:
        raise ValueError("È necessario fornire una password per la decrittografia")
    
    # Carica il file Excel criptato
    encrypted_df = pd.read_excel(input_file)
    
    # Decripta il DataFrame
    decrypted_df = decrypt_dataframe(encrypted_df, password)
    
    # Salva il DataFrame decriptato se specificato un file di output
    if output_file:
        decrypted_df.to_excel(output_file, index=False)
        print(f"File decriptato salvato in {output_file}")
    
    return decrypted_df

# Esempi di utilizzo
if __name__ == "__main__":
    # Esempio di crittografia con password
    # password = "la_mia_password_segreta"
    # encrypt_excel_file("dati.xlsx", "dati_criptati.xlsx", password)
    
    # Esempio di decrittografia con password
    # df = decrypt_excel_file("dati_criptati.xlsx", password="la_mia_password_segreta")
    # print(df.head())
    
    # In alternativa, salvare il risultato decriptato
    # decrypt_excel_file("dati_criptati.xlsx", "dati_decriptati.xlsx", password="la_mia_password_segreta")
    pass