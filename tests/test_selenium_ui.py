"""
run in pipeline bysetting setting RUN_SELENIUM=1 in github action
default is do not run
"""

import os

import pytest
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait


pytestmark = pytest.mark.skipif(
    os.environ.get("RUN_SELENIUM") != "1",
    reason="Set RUN_SELENIUM=1 when browser and running app are available",
)


@pytest.fixture
def driver():
    options = Options()
    options.add_argument("--headless=new")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--window-size=1280,1024")

    browser = webdriver.Chrome(options=options)
    browser.implicitly_wait(3)
    try:
        yield browser
    finally:
        browser.quit()


@pytest.fixture
def base_url():
    return os.environ.get("TEST_BASE_URL", "http://127.0.0.1:5000").rstrip("/")


def test_homepage_loads_in_browser(driver, base_url):
    driver.get(f"{base_url}/")

    assert "Secure Student Forum" in driver.title
    assert "Forums" in driver.page_source
    assert driver.find_element(By.LINK_TEXT, "Login").is_displayed()
    assert driver.find_element(By.LINK_TEXT, "Register").is_displayed()


def test_search_form_filters_forum_page(driver, base_url):
    driver.get(f"{base_url}/")

    search_box = driver.find_element(By.ID, "q")
    search_box.clear()
    search_box.send_keys("SQL")
    driver.find_element(By.CSS_SELECTOR, "button[type='submit']").click()

    WebDriverWait(driver, 5).until(EC.url_contains("q=SQL"))
    assert "SQL" in driver.page_source


def test_login_page_has_expected_fields(driver, base_url):
    driver.get(f"{base_url}/login")

    assert "Login" in driver.title
    assert driver.find_element(By.ID, "identifier").is_displayed()
    assert driver.find_element(By.ID, "password").is_displayed()
    assert driver.find_element(By.CSS_SELECTOR, "button[type='submit']").is_displayed()
