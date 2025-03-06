from encryptio_utils import encrypt_excel_file

# Cripta con una semplice password
encrypt_excel_file(
    "Dataset_telecamere_ascensore_5_piano_short.xlsx", 
    "mio_file_criptato.xlsx", 
    password="MiaPasswordSegreta"
)