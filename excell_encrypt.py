from encryptio_utils import encrypt_excel_file

# Cripta con una semplice password
encrypt_excel_file(
    "dati/10-camera AI tracking.xlsx", 
    "dati/10-camera AI tracking_crypted.xlsx", 
    password="KICKOFF25"
)