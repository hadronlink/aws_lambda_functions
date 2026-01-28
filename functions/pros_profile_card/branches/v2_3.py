import os
import json
import base64
import uuid
import urllib.request
from io import BytesIO

import boto3
# Added ImageChops to imports for compatibility with older PIL versions
from PIL import Image, ImageDraw, ImageFont, ImageOps, ImageChops

from google.oauth2 import service_account
from google.cloud import storage


# Initialize Google Storage client
try:
    creds_json = base64.b64decode(os.environ['GOOGLE_CREDENTIALS_JSON'])
    creds = service_account.Credentials.from_service_account_info(json.loads(creds_json))
    gcs_client = storage.Client(credentials=creds)
except KeyError:
    print("[WARNING] GOOGLE_CREDENTIALS_JSON env var not found. GCS upload will fail.")
    gcs_client = None
except Exception as e:
    print(f"[WARNING] Error loading Google Credentials: {e}. GCS upload will fail.")
    gcs_client = None

# Constants
BUCKET_NAME = 'hadronlink_pros_profile_cards'

# Color scheme matching the Flutter app
COLOR_SCHEME = {
    'primaryText': (49, 56, 134),   # #313886 (Dark Blue)
    'primaryBackground': (255, 255, 255),   # #FFFFFF
    'secondaryBackground': (247, 249, 253),   # #F7F9FD
    'gray60': (100, 110, 140),   # Darker grey for better readability
    'secondary': (22, 200, 221),   # #16C8DD (Cyan)
}

# Card dimensions (400x400 Square)
CARD_WIDTH = 400
CARD_HEIGHT = 400

# Header text translations
HEADER_TEXT = {
    # 'en': 'Visit my portfolio at',
    # 'pt': 'Visite meu portfólio em',
    # 'es': 'Visita mi portafolio en',
    # 'fr': 'Visitez mon portfolio sur',
    'en': '',
    'pt': '',
    'es': '',
    'fr': ''
}

# HadronLink logo URL
# HADRONLINK_LOGO_URL = 'https://storage.googleapis.com/hadronlink_platform_homepage_images/hadronlink_negative_horizontal_smaller_margin.png'
HADRONLINK_LOGO_URL = 'https://storage.googleapis.com/hadronlink_platform_homepage_images/only_connectus_smaller_logo.png'


def upload_to_gcs(image_bytes: bytes) -> str:
    if gcs_client is None:
         raise Exception("Google Cloud Storage client not initialized.")
    try:
        bucket = gcs_client.bucket(BUCKET_NAME)
        file_uuid = str(uuid.uuid4())
        filename = f"{file_uuid}.png"
        blob = bucket.blob(filename)
        blob.upload_from_string(image_bytes, content_type='image/png')
        url = f"https://storage.googleapis.com/{BUCKET_NAME}/{filename}"
        print(f"[DEBUG INFO] File uploaded to {url}")
        return url
    except Exception as e:
        print(f"[ERROR] Failed to upload image to Google Storage: {str(e)}")
        raise


def load_image_from_url(url: str) -> Image.Image:
    default_url = 'https://storage.googleapis.com/flutterflow-io-6f20.appspot.com/projects/hadronlink-f5o87i/assets/9yjr1333d3bh/NoImagePicture.png'
    try:
        if url:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=10) as response:
                return Image.open(BytesIO(response.read()))
    except Exception as e:
        print(f"Error loading image from {url}: {e}")
    try:
        req = urllib.request.Request(default_url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=10) as response:
            return Image.open(BytesIO(response.read()))
    except Exception as e:
        print(f"Error loading default image: {e}")
    return Image.new('RGB', (187, 187), COLOR_SCHEME['gray60'])


def create_circular_image(image: Image.Image, size: int) -> Image.Image:
    width, height = image.size
    new_size = min(width, height)
    left = (width - new_size) / 2
    top = (height - new_size) / 2
    right = (width + new_size) / 2
    bottom = (height + new_size) / 2
    image = image.crop((left, top, right, bottom))
    image = image.resize((size, size), Image.Resampling.LANCZOS)
    mask_size = (size * 4, size * 4)
    mask = Image.new('L', mask_size, 0)
    draw = ImageDraw.Draw(mask)
    draw.ellipse((0, 0) + mask_size, fill=255)
    mask = mask.resize((size, size), Image.Resampling.LANCZOS)
    output = Image.new('RGBA', (size, size), (0, 0, 0, 0))
    output.paste(image.convert('RGBA'), (0, 0))
    current_alpha = output.getchannel('A')
    new_alpha = ImageChops.multiply(current_alpha, mask)
    output.putalpha(new_alpha)
    return output


def draw_rounded_rectangle(draw: ImageDraw.Draw, xy: tuple, radius: int, fill: tuple):
    x1, y1, x2, y2 = xy
    radius = min(radius, (x2 - x1) // 2, (y2 - y1) // 2)
    draw.rectangle([x1 + radius, y1, x2 - radius, y2], fill=fill)
    draw.rectangle([x1, y1 + radius, x2, y2 - radius], fill=fill)
    draw.pieslice([x1, y1, x1 + radius * 2, y1 + radius * 2], 180, 270, fill=fill)
    draw.pieslice([x2 - radius * 2, y1, x2, y1 + radius * 2], 270, 0, fill=fill)
    draw.pieslice([x1, y2 - radius * 2, x1 + radius * 2, y2], 90, 180, fill=fill)
    draw.pieslice([x2 - radius * 2, y2 - radius * 2, x2, y2], 0, 90, fill=fill)


def load_logo_image() -> Image.Image:
    try:
        req = urllib.request.Request(HADRONLINK_LOGO_URL, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=10) as response:
            return Image.open(BytesIO(response.read()))
    except Exception as e:
        print(f"Error loading logo from {HADRONLINK_LOGO_URL}: {e}")
        return None


def mask_email(email: str) -> str:
    if not email or '@' not in email:
        return '****@***'
    try:
        user, domain_part = email.split('@')
        first_letter = user[:1] if user else "*"
        domain_parts = domain_part.split('.')
        tld = domain_parts[-1] if len(domain_parts) > 1 else "com"
        return f"{first_letter}***@***.{tld}"
    except:
        return email


def mask_phone(phone: str) -> str:
    if not phone:
        return ""
    parts = phone.split('-')
    if len(parts) >= 2:
         prefix = "-".join(parts[:-1])
         return f"{prefix}-****"
    elif len(phone) > 4:
         return phone[:-4] + "****"
    return phone


def generate_business_card(profile_data: dict) -> bytes:
    # 1. Setup Canvas
    card = Image.new('RGB', (CARD_WIDTH, CARD_HEIGHT), COLOR_SCHEME['primaryText'])
    draw = ImageDraw.Draw(card)

    # 2. Load Fonts
    font_header_size = 17
    font_name_size = 27
    font_title_size = 17
    font_info_size = 16
    font_tag_size = 15

    possible_font_paths = [
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
        "arial.ttf"
    ]
    possible_bold_font_paths = [
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf",
        "arialbd.ttf"
    ]

    def safe_load_font(paths, size):
        for path in paths:
            try:
                return ImageFont.truetype(path, size)
            except IOError: continue
        return ImageFont.load_default()

    font_header = safe_load_font(possible_font_paths, font_header_size)
    font_title = safe_load_font(possible_font_paths, font_title_size)
    font_info = safe_load_font(possible_font_paths, font_info_size)
    font_tag = safe_load_font(possible_font_paths, font_tag_size)
    font_name_bold = safe_load_font(possible_bold_font_paths, font_name_size)


    # 3. Draw Header Content (Top Dark Area)
    language = profile_data.get('language', 'en')
    header_text_str = HEADER_TEXT.get(language, HEADER_TEXT['en'])

    # Position header text (Moved further left for more spacing)
    header_text_x = 10
    header_text_y = 20
    draw.text((header_text_x, header_text_y), header_text_str, fill=COLOR_SCHEME['primaryBackground'], font=font_header, anchor='ls')

    # Load and position Logo (Moved further right for more spacing)
    logo = load_logo_image()
    if logo:
        logo_target_height = 20
        aspect_ratio = logo.width / logo.height
        logo_target_width = int(logo_target_height * aspect_ratio)
        logo = logo.resize((logo_target_width, logo_target_height), Image.Resampling.LANCZOS)

        logo_x = CARD_WIDTH - 10 - logo_target_width
        logo_y = header_text_y - logo_target_height + 3

        if logo.mode == 'RGBA':
            card.paste(logo, (logo_x, logo_y), logo)
        else:
            card.paste(logo, (logo_x, logo_y))

    # 4. Draw White Card Background
    card_margin_side = 16
    card_top_y = 33
    card_bottom_y = CARD_HEIGHT - card_margin_side

    draw_rounded_rectangle(
        draw,
        (card_margin_side, card_top_y, CARD_WIDTH - card_margin_side, card_bottom_y),
        5,
        COLOR_SCHEME['primaryBackground']
    )

    center_x = CARD_WIDTH // 2

    # 5. Profile Picture
    profile_pic_size = 115
    profile_pic_y = card_top_y + 7
    profile_pic_x = center_x - (profile_pic_size // 2)

    profile_image = load_image_from_url(profile_data.get('picture_url'))
    circular_profile = create_circular_image(profile_image, profile_pic_size)
    card.paste(circular_profile, (profile_pic_x, profile_pic_y), circular_profile)

    # 6. Text Content
    def get_text_height(text, font):
        bbox = draw.textbbox((0, 0), text, font=font)
        return bbox[3] - bbox[1]

    current_y = profile_pic_y + profile_pic_size + 20

    # Name (truncate if longer than 17 characters)
    name = profile_data.get('name', 'No name')
    if len(name) > 17:
        name = name[:17] + ''
    draw.text((center_x, current_y), name, fill=COLOR_SCHEME['primaryText'], font=font_name_bold, anchor='mm')
    current_y += get_text_height(name, font_name_bold) + 11

    # Trades/Title
    user_type = profile_data.get('user_type', 'Professional')
    trades = profile_data.get('trades', [])
    trade_text = ""
    if user_type == 'Professional' and trades:
        trade_text = ', '.join([str(t) for t in trades[:3]])
    elif user_type == 'Contractor' and trades:
         trade_text = ', '.join([str(t) for t in trades[:3]])

    if trade_text:
        draw.text((center_x, current_y), trade_text, fill=COLOR_SCHEME['primaryText'], font=font_title, anchor='mm')
        current_y += get_text_height(trade_text, font_title) + 8

    # Location
    location = profile_data.get('location', '')
    if location:
        draw.text((center_x, current_y), location.upper(), fill=COLOR_SCHEME['gray60'], font=font_title, anchor='mm')
        current_y += get_text_height(location, font_title) + 8

    # Contact Info
    email = profile_data.get('email', '')
    phone = profile_data.get('phone', '')
    masked_email = mask_email(email)
    masked_phone = mask_phone(phone)

    if email:
        email_text = f"email: {masked_email}"
        draw.text((center_x, current_y), email_text, fill=COLOR_SCHEME['gray60'], font=font_info, anchor='mm')
        current_y += get_text_height(email_text, font_info) + 8

    if phone:
        phone_text = f"phone: {masked_phone}"
        draw.text((center_x, current_y), phone_text, fill=COLOR_SCHEME['gray60'], font=font_info, anchor='mm')
        current_y += get_text_height(phone_text, font_info) + 3

    # 7. Tags (Smart row layout - max 3 tags, fit 2 per row if possible)
    if user_type == 'Professional':
        tags_text_list = [str(t) for t in profile_data.get('top_3_skills', [])][:3]
    else:
        tags_text_list = [str(t) for t in trades][:3]

    # Truncate tags longer than 33 characters
    tags_text_list = [t[:33] + '...' if len(t) > 33 else t for t in tags_text_list]

    if tags_text_list:
        tag_height = 24
        tag_padding_x = 11
        tag_margin_between = 4
        tag_horizontal_gap = 5

        # Maximum available width for tags in a row
        max_row_width = CARD_WIDTH - (card_margin_side * 2) - 14

        # Left align start X
        tag_start_x = card_margin_side + 7

        # Start Y: Add padding after the last element
        current_y += 2

        # Calculate width for each tag
        def get_tag_width(text):
            bbox = draw.textbbox((0, 0), text, font=font_tag)
            text_width = bbox[2] - bbox[0]
            return max(text_width, 10) + (tag_padding_x * 2)

        tag_widths = [get_tag_width(t) for t in tags_text_list]

        # Organize tags into rows based on fit
        rows = []
        if len(tags_text_list) == 1:
            rows.append([0])
        elif len(tags_text_list) >= 2:
            # Check if first 2 tags fit together on row 1
            if tag_widths[0] + tag_horizontal_gap + tag_widths[1] <= max_row_width:
                rows.append([0, 1])
                if len(tags_text_list) == 3:
                    rows.append([2])
            else:
                # Tag 1 alone on row 1, check if tag 2 and 3 fit together
                rows.append([0])
                if len(tags_text_list) == 3:
                    if tag_widths[1] + tag_horizontal_gap + tag_widths[2] <= max_row_width:
                        rows.append([1, 2])
                    else:
                        rows.append([1])
                        rows.append([2])
                else:
                    rows.append([1])

        # Draw each row of tags
        for row in rows:
            row_x = tag_start_x
            for idx in row:
                tag_text = tags_text_list[idx]
                pill_width = tag_widths[idx]

                # Draw tag background pill
                draw_rounded_rectangle(
                    draw,
                    (row_x, current_y, row_x + pill_width, current_y + tag_height),
                    tag_height // 2,
                    COLOR_SCHEME['secondary']
                )

                # Draw tag text centered in pill
                pill_center_x = row_x + (pill_width // 2)
                pill_center_y = current_y + (tag_height // 2) - 1
                draw.text((pill_center_x, pill_center_y), tag_text,
                          fill=COLOR_SCHEME['primaryBackground'], font=font_tag, anchor='mm')

                row_x += pill_width + tag_horizontal_gap

            # Move Y down for the next row
            current_y += tag_height + tag_margin_between

    buffer = BytesIO()
    card.save(buffer, format='PNG', optimize=True)
    return buffer.getvalue()


def handle_request(event, payload):
    """Main entry point for dev branch"""
    headers = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Access-Control-Allow-Methods': 'OPTIONS,POST,GET'
    }
    try:
        operation = event.get('httpMethod')
        if operation == 'OPTIONS':
            return {'statusCode': 200, 'headers': headers, 'body': ''}

        result = create_profile_card(payload)
        result['headers'] = {**headers, **result.get('headers', {})}
        return result

    except Exception as e:
        print(f"Handle Request Error: {e}")
        import traceback
        traceback.print_exc()
        return {'statusCode': 500, 'headers': headers, 'body': json.dumps({'error': str(e)})}


def create_profile_card(payload):
    try:
        user_type = payload.get('user_type')
        if user_type not in ['Professional', 'Contractor']:
            return {'statusCode': 400, 'body': json.dumps({'error': "user_type must be 'Professional' or 'Contractor'"})}

        profile_data = {
            'user_type': user_type,
            'profile_id': payload.get('profile_id'),
            'language': payload.get('language', 'en'),
            'picture_url': payload.get('picture_url'),
            'name': payload.get('name', 'No name'),
            'trades': payload.get('trades', []),
            'location': payload.get('location', ''),
            'email': payload.get('email', ''),
            'phone': payload.get('phone', ''),
            'top_3_skills': payload.get('top_3_skills', []),
        }

        print(f"Generating card for data: {json.dumps(profile_data)}")
        image_bytes = generate_business_card(profile_data)
        url = upload_to_gcs(image_bytes)

        return {'statusCode': 200, 'body': json.dumps({'success': True, 'url': url,})}

    except Exception as e:
        print(f"[ERROR] Failed to create profile card: {str(e)}")
        import traceback
        traceback.print_exc()
        return {'statusCode': 500, 'body': json.dumps({'error': str(e)})}
