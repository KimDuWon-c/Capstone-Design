It is a project utilizing Open source 'Dangerzone'

In this project, adding HWP file extension a lot of koreans use.

Convert hwp to html through pyhwp and html to pdf through wkhtmltopdf.

Must install Korean Package.

If you want searchable PDF file. Execute following command for tesseract

docker run --network none -v [pixel_dir]:/dangerzone -v [safe_dir]:/safezone [container_name] -e OCR=[ocr] -e OCR_LANGUAGE=[ocr_lang] document-to-pdf.sh
  
Or if you want flat PDF file, Excute following command

docker run --network none -v [pixel_dir]:/dangerzone -v [safe_dir]:/safezone [container_name] document-to-pdf.sh
