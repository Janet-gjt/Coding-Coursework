This submission contains my image enhancement program for the
X-ray dataset. The script processes all images in a specified
directory and saves the enhanced results into a folder named
"Results", as required in the specification.

The program is written in Python and only uses OpenCV (cv2) and
NumPy, which are available on the Durham University lab PCs.
No additional external libraries are required.

To run the program, navigate to the folder containing main.py
and execute:

    python main.py image_processing_files/xray_images/

The script will iterate through all images in the given directory,
process them one by one, and save the outputs into the "Results"
folder. The folder is created automatically if it does not exist.
The same script can also be used for unseen test images.

The output images keep the original filenames and resolution.
No extra directories are created by the program.

The processing pipeline first reduces mixed noise using a median
filter followed by non-local means denoising on the luminance
channel. The entire image is then analysed to automatically detect
any dark circular artefact using intensity, area and circularity
criteria. When a valid defect is found, Telea inpainting is applied
conditionally.

After that, CLAHE is applied on the luminance channel to improve
local contrast, followed by automatic gamma normalisation to
stabilise brightness. A mild unsharp mask is finally applied, with
an additional detail-protection step to avoid over-smoothing.

Each image is processed independently and the method does not rely
on any fixed region-of-interest assumptions.