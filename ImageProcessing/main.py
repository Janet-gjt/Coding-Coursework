import argparse
from pathlib import Path
import cv2
import numpy as np


def parse_args():
    parser = argparse.ArgumentParser(
        description="COMP2271 Image Processing Coursework - main runner"
    )
    parser.add_argument(
        "input_dir",
        type=str,
        help="Path to directory containing input images",
    )
    return parser.parse_args()


def denoise_bgr(img_bgr: np.ndarray) -> np.ndarray:
    med = cv2.medianBlur(img_bgr, 3)
    ycrcb = cv2.cvtColor(med, cv2.COLOR_BGR2YCrCb)
    y, cr, cb = cv2.split(ycrcb)
    y_d = cv2.fastNlMeansDenoising(
        y,
        None,
        h=6,
        templateWindowSize=7,
        searchWindowSize=21,
    )
    out = cv2.merge([y_d, cr, cb])
    return cv2.cvtColor(out, cv2.COLOR_YCrCb2BGR)


def detect_missing_circle_mask(img_bgr: np.ndarray):
    gray = cv2.cvtColor(img_bgr, cv2.COLOR_BGR2GRAY)
    h, w = gray.shape
    _, thr = cv2.threshold(gray, 25, 255, cv2.THRESH_BINARY_INV)
    kernel = np.ones((5, 5), np.uint8)
    thr = cv2.morphologyEx(thr, cv2.MORPH_OPEN, kernel, iterations=1)
    thr = cv2.morphologyEx(thr, cv2.MORPH_CLOSE, kernel, iterations=2)
    contours, _ = cv2.findContours(thr, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
    if not contours:
        return np.zeros_like(gray, dtype=np.uint8), False
    best_score = 0
    best_mask = None
    img_area = h * w
    for c in contours:
        area = cv2.contourArea(c)
        if area < 500 or area > 0.2 * img_area:
            continue
        peri = cv2.arcLength(c, True)
        if peri <= 1:
            continue
        circularity = (4 * np.pi * area) / (peri * peri)
        if circularity < 0.5:
            continue
        mask = np.zeros_like(gray, dtype=np.uint8)
        cv2.drawContours(mask, [c], -1, 255, thickness=-1)
        mean_val = cv2.mean(gray, mask=mask)[0]
        darkness_score = max(0, 80 - mean_val)
        score = circularity * 0.6 + (darkness_score / 80.0) * 0.4
        if score > best_score:
            best_score = score
            best_mask = mask
    if best_mask is None:
        return np.zeros_like(gray, dtype=np.uint8), False
    k2 = cv2.getStructuringElement(cv2.MORPH_ELLIPSE, (7, 7))
    best_mask = cv2.dilate(best_mask, k2, iterations=1)
    return best_mask, True


def inpaint_missing_region(img_bgr: np.ndarray, mask: np.ndarray) -> np.ndarray:
    return cv2.inpaint(img_bgr, mask, inpaintRadius=3, flags=cv2.INPAINT_TELEA)


def clahe_on_luminance(img_bgr: np.ndarray) -> np.ndarray:
    ycrcb = cv2.cvtColor(img_bgr, cv2.COLOR_BGR2YCrCb)
    y, cr, cb = cv2.split(ycrcb)
    clahe = cv2.createCLAHE(clipLimit=1.6, tileGridSize=(8, 8))
    y2 = clahe.apply(y)
    out = cv2.merge([y2, cr, cb])
    return cv2.cvtColor(out, cv2.COLOR_YCrCb2BGR)


def auto_gamma(img_bgr: np.ndarray, target_mean: float = 115.0) -> np.ndarray:
    y = cv2.cvtColor(img_bgr, cv2.COLOR_BGR2YCrCb)[:, :, 0].astype(np.float32)
    m = float(np.mean(y)) / 255.0
    t = float(target_mean) / 255.0
    m = min(max(m, 1e-3), 0.999)
    t = min(max(t, 1e-3), 0.999)
    gamma = np.log(m) / np.log(t)
    gamma = float(np.clip(gamma, 0.85, 1.20))
    inv = 1.0 / gamma
    table = (np.arange(256) / 255.0) ** inv * 255.0
    table = np.clip(table, 0, 255).astype(np.uint8)
    return cv2.LUT(img_bgr, table)


def mild_sharpen(img_bgr: np.ndarray) -> np.ndarray:
    blur = cv2.GaussianBlur(img_bgr, (0, 0), 1.0)
    sharp = cv2.addWeighted(img_bgr, 1.12, blur, -0.12, 0)
    return sharp


def protect_detail_if_too_smooth(img_bgr: np.ndarray) -> np.ndarray:
    gray = cv2.cvtColor(img_bgr, cv2.COLOR_BGR2GRAY)
    v = cv2.Laplacian(gray, cv2.CV_64F).var()
    if v < 18.0:
        ycrcb = cv2.cvtColor(img_bgr, cv2.COLOR_BGR2YCrCb)
        y, cr, cb = cv2.split(ycrcb)
        clahe = cv2.createCLAHE(clipLimit=1.2, tileGridSize=(8, 8))
        y2 = clahe.apply(y)
        out = cv2.merge([y2, cr, cb])
        return cv2.cvtColor(out, cv2.COLOR_YCrCb2BGR)
    return img_bgr


def process_one(img: np.ndarray) -> np.ndarray:
    x = denoise_bgr(img)
    mask, ok = detect_missing_circle_mask(x)
    if ok:
        x = inpaint_missing_region(x, mask)
    x = clahe_on_luminance(x)
    x = auto_gamma(x, target_mean=115.0)
    x = mild_sharpen(x)
    x = protect_detail_if_too_smooth(x)
    return x


def main():
    args = parse_args()
    input_dir = Path(args.input_dir)
    if not input_dir.exists() or not input_dir.is_dir():
        raise FileNotFoundError(f"Input directory not found: {input_dir}")
    results_dir = Path("Results")
    results_dir.mkdir(exist_ok=True)
    img_paths = sorted(
        [
            p for p in input_dir.iterdir()
            if p.suffix.lower() in [".jpg", ".jpeg", ".png"]
        ]
    )
    saved = 0
    for p in img_paths:
        img = cv2.imread(str(p), cv2.IMREAD_COLOR)
        if img is None:
            continue
        out = process_one(img)
        cv2.imwrite(str(results_dir / p.name), out)
        saved += 1
    print(f"Done. Saved {saved} images to {results_dir}/")


if __name__ == "__main__":
    main()