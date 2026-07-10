"""
run in pipeline bysetting setting RUN_SELENIUM=1 in github action
default is do not run
"""

import os
import uuid

import pytest
from selenium import webdriver
from selenium.webdriver.support.ui import Select
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import Select
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

def test_user_registration_login_post_creation_and_logout(driver, base_url):
    unique_suffix = uuid.uuid4().hex[:8]
    username = f"student_{unique_suffix}"
    email = f"{username}@example.edu"
    password = "SecureForum!2026"

    post_title = f"Selenium security test {unique_suffix}"
    post_body = (
        "This post verifies registration, login, authenticated post creation, "
        "logout, and protected-route enforcement."
    )

    wait = WebDriverWait(driver, 10)

    # Register a unique account.
    driver.get(f"{base_url}/register")

    driver.find_element(By.ID, "username").send_keys(username)
    driver.find_element(By.ID, "email").send_keys(email)
    driver.find_element(By.ID, "password").send_keys(password)
    driver.find_element(By.ID, "confirm_password").send_keys(password)
    driver.find_element(
        By.CSS_SELECTOR,
        "button[type='submit']",
    ).click()

    wait.until(
        lambda current_driver: current_driver.execute_script(
            "return document.readyState"
        ) == "complete"
    )

    assert "/login" in driver.current_url, (
        "Registration did not redirect to login.\n"
        f"Current URL: {driver.current_url}\n"
        f"Page text:\n{driver.find_element(By.TAG_NAME, 'body').text}"
    )

    assert "Registration successful" in driver.find_element(
        By.TAG_NAME,
        "body",
    ).text

    # Log in with the newly registered account.
    driver.find_element(By.ID, "identifier").send_keys(username)
    driver.find_element(By.ID, "password").send_keys(password)
    driver.find_element(
        By.CSS_SELECTOR,
        "button[type='submit']",
    ).click()

    wait.until(
        EC.presence_of_element_located(
            (By.LINK_TEXT, "New Post")
        )
    )

    assert "Logout" in driver.page_source
    assert username not in driver.current_url

    # Create a forum post through the authenticated UI.
    driver.find_element(By.LINK_TEXT, "New Post").click()

    wait.until(EC.url_contains("/posts/new"))

    driver.find_element(By.ID, "title").send_keys(post_title)

    category = Select(driver.find_element(By.ID, "category"))
    category.select_by_visible_text("Cybersecurity")

    driver.find_element(By.ID, "body").send_keys(post_body)
    driver.find_element(
        By.CSS_SELECTOR,
        "button[type='submit']",
    ).click()

    wait.until(
        EC.text_to_be_present_in_element(
            (By.TAG_NAME, "body"),
            post_title,
        )
    )

    assert "/posts/" in driver.current_url
    assert post_title in driver.page_source
    assert post_body in driver.page_source
    assert "Post created." in driver.page_source

    # Log out using the CSRF-protected navigation form.
    logout_button = driver.find_element(
        By.XPATH,
        "//button[normalize-space()='Logout']",
    )
    logout_button.click()

    wait.until(EC.url_contains("/login"))

    assert "You have been logged out." in driver.page_source
    assert driver.find_element(By.LINK_TEXT, "Login").is_displayed()
    assert driver.find_element(By.LINK_TEXT, "Register").is_displayed()

    # Confirm a logged-out browser cannot access a protected route.
    driver.get(f"{base_url}/posts/new")

    wait.until(EC.url_contains("/login"))

    assert "/login" in driver.current_url
    assert "New Post" not in driver.page_source