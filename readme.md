<searchable PDF>
docker run --network none -v [pixel_dir]:/dangerzone -v [safe_dir]:/safezone [container_name] -e OCR=[ocr] -e OCR_LANGUAGE=[ocr_lang] pixels-to-pdf
  
<flat PDF>
docker run --network none -v [pixel_dir]:/dangerzone -v [safe_dir]:/safezone [container_name] pixels-to-pdf
