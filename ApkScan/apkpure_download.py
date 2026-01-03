import re
from urllib.parse import urljoin
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import os
from tqdm import tqdm

# List of package version pages
packages = [

    "com.medtronic.diabetes.fota",
    "com.medtronic.diabetes.minimedclinical",
    "com.medtronic.diabetes.fota.us",
    "com.medtronic.diabetes.guardianclinical",
    "com.medtronic.diabetes.minimedmobile.eu",
    "com.medtronic.diabetes.guardianconnect",
    "com.medtronic.diabetes.minimedmobile.us",
    "com.medtronic.diabetes.guardian",
    "com.medtronic.diabetes.guardianconnect.us",
    "com.medtronic.diabetes.simplera.eu",

]

def create_driver():
    """Create a headless Selenium Chrome driver."""
    chrome_options = Options()
    chrome_options.add_argument("--headless")
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--no-sandbox")
    driver = webdriver.Chrome(options=chrome_options)
    return driver

def get_version_download_pages(driver, versions_url):
    """Get all individual version download page URLs from the /versions page."""
    driver.get(versions_url)

    # Wait until download buttons appear
    WebDriverWait(driver, 10).until(
        EC.presence_of_all_elements_located((By.CSS_SELECTOR, "a.download-btn"))
    )

    version_links = []
    for a_tag in driver.find_elements(By.CSS_SELECTOR, "a.download-btn"):
        href = a_tag.get_attribute("href")
        if href and "/download/" in href:
            full_url = urljoin(versions_url, href)
            version_links.append(full_url)
    return version_links

def get_final_dl_link(driver, download_page_url):
    """Get the final APK download link from a version download page."""
    driver.get(download_page_url)

    try:
        # Wait until the final APK link appears
        a_tag = WebDriverWait(driver, 10).until(
            EC.presence_of_element_located((By.CSS_SELECTOR, "a[href*='/b/APK'], a[href*='/b/XAPK']"))
        )
        return a_tag.get_attribute("href")
    except:
        return None

def download_apk(apk_url, original_page_url):
    """Placeholder download function."""
    #print(f"[DEBUG] Would download {apk_url} from {original_page_url}")
    ver_code = original_page_url.split("/")[-1]
    pkg = original_page_url.split("/")[-3]
    ext = ".apk"
    if "XAPK" in apk_url:
        ext = ".xapk"
    fn = pkg + "_" + ver_code + ext #.replace(".", "_")
    print(apk_url + " -> " + fn)
    
    
    if not os.path.isfile(fn):
        os.system(f'aria2c -x 16 -s 16 -o "{fn}" "{apk_url}"')




driver = create_driver()

start_dir = os.path.abspath(os.getcwd())


for package_name in packages:


    url = f"https://apkpure.net/{package_name.replace('.', '-')}/{package_name}/versions"

    os.chdir(start_dir)

    if not os.path.isdir(package_name):
        os.mkdir(package_name)
        os.chdir(package_name)

    print(f"Processing url: {url}")
    version_pages = get_version_download_pages(driver, url)

    for version_page_url in version_pages:
        final_link = get_final_dl_link(driver, version_page_url)
        if final_link:
            download_apk(final_link, version_page_url)
        else:
            print(f"[WARN] No APK link found on {version_page_url}")

driver.quit()
