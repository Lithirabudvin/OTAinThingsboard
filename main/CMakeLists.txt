idf_component_register(
    SRCS "main.c"
         "wifi.c"
    INCLUDE_DIRS "."
    # EMBED_TXTFILES ${PROJECT_DIR}/server_certs/ca_cert.pem
)
