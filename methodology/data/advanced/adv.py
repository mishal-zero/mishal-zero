import requests
from bs4 import BeautifulSoup
import json
import time

# Base URL
BASE_URL = "https://www.muktifresh.in/customer/editaddress/"

# Session cookies
COOKIES = {
    "_gid": "GA1.2.1496821759.1749983861",
    "muktifresh_session": "r1fvpbkhjviqakrlmvcjlvuspt98fb07",
    "TawkConnectionTime": "0",
    "twk_uuid_64f2e122a91e863a5c112fdf": "%7B%22uuid%22%3A%221.1vXSkyKQqsAImLnyYYsWVHIwtQPJlTt7cXwsIoZEQTstYHAVljwPpWWJqjNRbDk66B6NTo3FYkYWLRrJ3Y5atkSY4onBKDpd9OIq7l06g0th8fU4xGTXaTW%22%2C%22version%22%3A3%2C%22domain%22%3A%22muktifresh.in%22%2C%22ts%22%3A1750009083271%7D",
    "_ga_61L2GTWMN3": "GS2.1.s1750007414$o5$g1$t1750009079$j19$l0$h0",
    "_fbp": "fb.1.1749482664031.5700192529363926",
    "_ga": "GA1.1.1746291861.1749482664",
    "_ga_DC3Q3DSH26": "GS2.2.s1750007415$o5$g1$t1750009080$j22$l0$h0",
    "_gcl_au": "1.1.264328599.1749482664",
    "muktiFreshSecure": "d0daf6adb40fa621c701ef99e69b2971fc049855"
}

HEADERS = {
    "User-Agent": "Mozilla/5.0"
}

# Output file
JSON_FILE = "form_data.json"

def scrape_form_data(start_id=1, end_id=3000):
    results = []

    for i in range(start_id, end_id + 1):
        url = f"{BASE_URL}{i}"
        print(f"Scraping ID: {i} -> {url}")

        try:
            response = requests.get(url, cookies=COOKIES, headers=HEADERS, timeout=10)
            soup = BeautifulSoup(response.text, "html.parser")
            form = soup.find("form", {"action": "https://www.muktifresh.in/customer/addUpdate/"})

            if not form:
                print(f"No form found for ID {i}")
                continue

            data = {"url_id": i}
            filled_fields = 0

            # Extract input fields
            for input_tag in form.find_all("input"):
                name = input_tag.get("name")
                value = input_tag.get("value", "").strip()
                if name:
                    data[name] = value
                    if value:
                        filled_fields += 1

            # Extract textarea 'address'
            textarea = form.find("textarea", {"name": "address"})
            if textarea:
                address_value = textarea.text.strip()
                data["address"] = address_value
                if address_value:
                    filled_fields += 1

            # Extract select 'location'
            location_select = form.find("select", {"name": "location"})
            if location_select:
                selected = location_select.find("option", selected=True)
                if selected:
                    location_value = selected.get("value", "").strip()
                else:
                    location_value = location_select.find("option").get("value", "").strip()  # fallback
                data["location"] = location_value
                if location_value:
                    filled_fields += 1

            # Extract select 'housing'
            housing_select = form.find("select", {"name": "housing"})
            if housing_select:
                selected = housing_select.find("option", selected=True)
                if selected:
                    housing_value = selected.get("value", "").strip()
                else:
                    housing_value = housing_select.find("option").get("value", "").strip()  # fallback
                data["housing"] = housing_value
                if housing_value:
                    filled_fields += 1

            # Skip if no meaningful data
            if filled_fields == 0:
                print(f"Skipping ID {i} — no data in form.")
                continue

            results.append(data)
            time.sleep(1)

        except Exception as e:
            print(f"Error scraping ID {i}: {e}")

    # Save to JSON
    with open(JSON_FILE, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
        print(f"\n✅ Finished. {len(results)} entries saved to {JSON_FILE}")

if __name__ == "__main__":
    scrape_form_data(1, 3000)

