import os
import json
import base64
import uuid
import urllib.request
from io import BytesIO

import boto3
from boto3.dynamodb.conditions import Key

from PIL import Image, ImageDraw, ImageFont

from google.oauth2 import service_account
from google.cloud import storage


# Initialize DynamoDB resources
dynamodb = boto3.resource('dynamodb')

# Initialize Google Storage client
creds_json = base64.b64decode(os.environ['GOOGLE_CREDENTIALS_JSON'])
creds = service_account.Credentials.from_service_account_info(json.loads(creds_json))
gcs_client = storage.Client(credentials=creds)

# Constants
BUCKET_NAME = 'hadronlink_pros_profile_cards'

# Color scheme matching the Flutter app
COLOR_SCHEME = {
    'primaryText': (49, 56, 134),  # #313886
    'primaryBackground': (255, 255, 255),  # #FFFFFF
    'secondaryBackground': (247, 249, 253),  # #F7F9FD
    'gray60': (100, 110, 140),  # Darker grey for better readability
    'secondary': (22, 200, 221),  # #16C8DD
}

# Card dimensions
CARD_WIDTH = 900
CARD_HEIGHT = 450

# Header text translations
HEADER_TEXT = {
    'en': 'Visit my portfolio at',
    'pt': 'Visite meu portfólio em',
    'es': 'Visita mi portafolio en',
    'fr': 'Visitez mon portfolio sur',
}

# HadronLink logo URL
HADRONLINK_LOGO_URL = 'https://storage.googleapis.com/hadronlink_platform_homepage_images/hadronlink_negative_horizontal_smaller_margin.png'


def upload_to_gcs(image_bytes: bytes) -> str:
    """
    Upload image bytes to Google Cloud Storage.

    Args:
        image_bytes: PNG image as bytes

    Returns:
        The public URL of the uploaded file
    """
    try:
        bucket = gcs_client.bucket(BUCKET_NAME)

        # Generate filename with dev_ prefix and UUID
        file_uuid = str(uuid.uuid4())
        filename = f"dev_{file_uuid}"

        blob = bucket.blob(filename)
        blob.upload_from_string(image_bytes, content_type='image/png')

        # Build the public URL
        url = f"https://storage.googleapis.com/{BUCKET_NAME}/{filename}"

        print(f"[DEBUG INFO] File uploaded to {url}")

        return url

    except Exception as e:
        print(f"[ERROR] Failed to upload image to Google Storage: {str(e)}")
        raise


def load_image_from_url(url: str) -> Image.Image:
    """
    Load an image from a URL.

    Args:
        url: The URL to load the image from

    Returns:
        PIL Image object
    """
    default_url = 'https://storage.googleapis.com/flutterflow-io-6f20.appspot.com/projects/hadronlink-f5o87i/assets/9yjr1333d3bh/NoImagePicture.png'

    try:
        if url:
            with urllib.request.urlopen(url, timeout=10) as response:
                return Image.open(BytesIO(response.read()))
    except Exception as e:
        print(f"Error loading image from {url}: {e}")

    # Try default URL
    try:
        with urllib.request.urlopen(default_url, timeout=10) as response:
            return Image.open(BytesIO(response.read()))
    except Exception as e:
        print(f"Error loading default image: {e}")

    # Return a placeholder gray circle
    return Image.new('RGB', (140, 140), COLOR_SCHEME['gray60'])


def create_circular_image(image: Image.Image, size: int) -> Image.Image:
    """
    Create a circular version of an image.

    Args:
        image: The source image
        size: The diameter of the circular image

    Returns:
        Circular PIL Image with transparent background
    """
    # Crop to square first to avoid stretching
    width, height = image.size
    if width != height:
        new_size = min(width, height)
        left = (width - new_size) / 2
        top = (height - new_size) / 2
        right = (width + new_size) / 2
        bottom = (height + new_size) / 2
        image = image.crop((left, top, right, bottom))

    # Resize image to target size
    image = image.resize((size, size), Image.Resampling.LANCZOS)

    # Create circular mask
    mask = Image.new('L', (size, size), 0)
    draw = ImageDraw.Draw(mask)
    draw.ellipse((0, 0, size, size), fill=255)

    # Create output with transparency
    output = Image.new('RGBA', (size, size), (0, 0, 0, 0))
    output.paste(image.convert('RGB'), (0, 0))
    output.putalpha(mask)

    return output


def draw_rounded_rectangle(draw: ImageDraw.Draw, xy: tuple, radius: int, fill: tuple):
    """
    Draw a rounded rectangle.

    Args:
        draw: ImageDraw object
        xy: Tuple of (x1, y1, x2, y2)
        radius: Corner radius
        fill: Fill color tuple
    """
    x1, y1, x2, y2 = xy
    draw.rectangle([x1 + radius, y1, x2 - radius, y2], fill=fill)
    draw.rectangle([x1, y1 + radius, x2, y2 - radius], fill=fill)
    draw.ellipse([x1, y1, x1 + radius * 2, y1 + radius * 2], fill=fill)
    draw.ellipse([x2 - radius * 2, y1, x2, y1 + radius * 2], fill=fill)
    draw.ellipse([x1, y2 - radius * 2, x1 + radius * 2, y2], fill=fill)
    draw.ellipse([x2 - radius * 2, y2 - radius * 2, x2, y2], fill=fill)


def load_logo_image() -> Image.Image:
    """
    Load the HadronLink logo from URL.

    Returns:
        PIL Image object or None if failed
    """
    try:
        with urllib.request.urlopen(HADRONLINK_LOGO_URL, timeout=10) as response:
            return Image.open(BytesIO(response.read()))
    except Exception as e:
        print(f"Error loading logo from {HADRONLINK_LOGO_URL}: {e}")
        return None


def mask_email(email: str) -> str:
    """Masks email address (e.g., j***@***.com)."""
    if not email or '@' not in email:
        return '****@***'
    try:
        user, domain = email.split('@')
        if '.' in domain:
            extension = domain.split('.')[-1]
            return f"{user[:1]}***@***.{extension}"
        return f"{user[:1]}***@***"
    except:
        return email


def mask_phone(phone: str) -> str:
    """Masks last 4 digits of phone number."""
    if not phone:
        return phone
    if len(phone) > 4:
        return phone[:-4] + "****"
    return phone


def generate_business_card(profile_data: dict) -> bytes:
    """
    Generate a business card image from profile data.

    Args:
        profile_data: Dictionary containing profile information
            - user_type: 'Professional' or 'Contractor'
            - name: Display name
            - picture_url: Profile picture URL
            - trades: List of trades (1 for Professional, up to 3 for Contractor)
            - location: City, State, Country string
            - email: Email address
            - phone: Phone number
            - top_3_skills: List of skills (up to 3 for Professional, empty for Contractor)
            - language: 'en', 'pt', 'es', or 'fr'

    Returns:
        PNG image as bytes
    """
    # Create the card image with higher resolution for better quality
    card = Image.new('RGB', (CARD_WIDTH, CARD_HEIGHT), COLOR_SCHEME['primaryText'])
    draw = ImageDraw.Draw(card)

    # Try to load fonts with better sizes (fallback to default if not available)
    font_large = 40
    font_medium = 26
    font_small = 26
    font_xsmall = 20

    try:
        font_header = ImageFont.truetype("arial.ttf", font_large)
        font_name = ImageFont.truetype("arial.ttf", font_large)
        font_trade = ImageFont.truetype("arial.ttf", font_large)
        font_info = ImageFont.truetype("arial.ttf", font_large)
        font_tag = ImageFont.truetype("arial.ttf", font_small)
    except:
        try:
            # Try common Linux font path (e.g. AWS Lambda)
            font_header = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 28)
            font_name = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", font_large)
            font_trade = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", font_medium)
            font_info = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", font_small)
            font_tag = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", font_small)
        except:
            font_header = ImageFont.load_default()
            font_name = ImageFont.load_default()
            font_trade = ImageFont.load_default()
            font_info = ImageFont.load_default()
            font_tag = ImageFont.load_default()

    # Get header text based on language
    language = profile_data.get('language', 'en')
    header_text = HEADER_TEXT.get(language, HEADER_TEXT['en'])

    # Draw header text on left side
    draw.text((180, 20), header_text, fill=COLOR_SCHEME['primaryBackground'], font=font_header)

    # Load and draw HadronLink logo on right side of header
    logo = load_logo_image()
    if logo:
        # Resize logo to fit in header (maintaining aspect ratio)
        logo_height = 55
        aspect_ratio = logo.width / logo.height
        logo_width = int(logo_height * aspect_ratio)
        logo = logo.resize((logo_width, logo_height), Image.Resampling.LANCZOS)

        # Position logo on the right side of the header
        logo_x = CARD_WIDTH - logo_width - 100
        logo_y = 10

        # Handle transparency if logo has alpha channel
        if logo.mode == 'RGBA':
            card.paste(logo, (logo_x, logo_y), logo)
        else:
            card.paste(logo, (logo_x, logo_y))

    # Draw the inner card background (rounded rectangle)
    inner_margin = 20
    inner_top = 70
    draw_rounded_rectangle(
        draw,
        (inner_margin, inner_top, CARD_WIDTH - inner_margin, CARD_HEIGHT - inner_margin),
        20,
        COLOR_SCHEME['primaryBackground']
    )

    # Load and draw profile picture (larger size)
    profile_pic_size = 200
    profile_pic_x = inner_margin + 30
    profile_pic_y = inner_top + 30

    profile_image = load_image_from_url(profile_data.get('picture_url'))
    circular_profile = create_circular_image(profile_image, profile_pic_size)

    # Paste circular image onto card
    card.paste(circular_profile, (profile_pic_x, profile_pic_y), circular_profile)

    # Text position (to the right of the profile picture)
    text_x = profile_pic_x + profile_pic_size + 40
    text_y = profile_pic_y + 10

    # Draw name (larger, bold)
    name = profile_data.get('name', 'No name')
    draw.text((text_x, text_y), name, fill=COLOR_SCHEME['primaryText'], font=font_name)
    text_y += 48

    # For Professionals: show trade below name
    user_type = profile_data.get('user_type', 'Professional')
    trades = profile_data.get('trades', [])

    if user_type == 'Professional' and trades:
        # Show first trade below name (can show multiple trades separated by comma)
        trade_text = ', '.join(trades[:3]) if len(trades) > 1 else trades[0]
        trade_text = trade_text if isinstance(trade_text, str) else str(trade_text)
        draw.text((text_x, text_y), trade_text, fill=COLOR_SCHEME['primaryText'], font=font_trade)
        text_y += 34

    # Draw location
    location = profile_data.get('location', '')
    if location:
        draw.text((text_x, text_y), location, fill=COLOR_SCHEME['gray60'], font=font_info)
        text_y += 34

    is_from_bot = profile_data.get('is_from_bot', True)

    # Draw email
    email = profile_data.get('email', '')
    if email:
        if is_from_bot:
            masked_email = mask_email(email)
            draw.text((text_x, text_y), f"email: {masked_email}", fill=COLOR_SCHEME['gray60'], font=font_info)
        else:
            draw.text((text_x, text_y), email, fill=COLOR_SCHEME['gray60'], font=font_info)
        text_y += 34

    # Draw phone (full number)
    phone = profile_data.get('phone', '')
    if phone:
        if is_from_bot:
            masked_phone = mask_phone(phone)
            draw.text((text_x, text_y), f"phone: {masked_phone}", fill=COLOR_SCHEME['gray60'], font=font_info)
        else:
            draw.text((text_x, text_y), phone, fill=COLOR_SCHEME['gray60'], font=font_info)

    # Draw tags based on user type
    # Professional: top_3_skills as tags
    # Contractor: trades as tags (up to 3)
    if user_type == 'Professional':
        tags = profile_data.get('top_3_skills', [])
    else:
        tags = trades[:3] if trades else []

    if tags:
        tag_y = CARD_HEIGHT - inner_margin - 100
        tag_x = inner_margin + 30
        tag_height = 36
        tag_padding = 20
        tag_margin = 12

        for tag in tags:
            tag_text = tag if isinstance(tag, str) else str(tag)

            # Calculate tag width based on text
            try:
                bbox = draw.textbbox((0, 0), tag_text, font=font_tag)
                tag_width = bbox[2] - bbox[0] + tag_padding * 2
            except:
                tag_width = len(tag_text) * 10 + tag_padding * 2

            # Check if tag fits on current line
            if tag_x + tag_width > CARD_WIDTH - inner_margin - 20:
                tag_x = inner_margin + 30
                tag_y += tag_height + 8

            # Check if we've gone past the card height
            if tag_y + tag_height > CARD_HEIGHT - inner_margin - 10:
                break

            # Draw tag background with rounded corners
            draw_rounded_rectangle(
                draw,
                (tag_x, tag_y, tag_x + tag_width, tag_y + tag_height),
                18,
                COLOR_SCHEME['secondary']
            )

            # Draw tag text (centered vertically)
            draw.text((tag_x + tag_padding, tag_y + tag_height // 2), tag_text,
                      fill=COLOR_SCHEME['primaryBackground'], font=font_tag, anchor='lm')

            tag_x += tag_width + tag_margin

    # Convert to bytes
    buffer = BytesIO()
    card.save(buffer, format='PNG')
    return buffer.getvalue()


def lambda_handler(event, context):
    """
    AWS Lambda handler function.

    Expected event format (API Gateway proxy integration):
    {
        "httpMethod": "POST",
        "body": "{\"user_type\": \"Professional\", ...}"
    }

    Expected body format:
    {
        "user_type": "Professional" or "Contractor",
        "profile_id": 123,
        "language": "en" | "pt" | "es",
        "picture_url": "https://...",
        "name": "John Doe",
        "trades": ["Trade1", "Trade2", "Trade3"],  # 1 for Professional, up to 3 for Contractor
        "location": "TORONTO, ON, CA",
        "email": "email@example.com",
        "phone": "+1 647 336-3333",
        "top_3_skills": ["Skill1", "Skill2", "Skill3"]  # Up to 3 for Professional, empty for Contractor
    }

    Returns:
        JSON with the uploaded filename or error response
    """
    operation = event['httpMethod']
    payload = event['queryStringParameters'] if operation == 'GET' else json.loads(event['body']) if event.get('body') else {}

    try:
        if operation == 'POST':
            return create_profile_card(payload)
        else:
            return {
                'statusCode': 400,
                'body': json.dumps({'error': 'Invalid HTTP method'})
            }
    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }


def create_profile_card(payload):
    """
    Create a profile card image and upload it to Google Cloud Storage.

    Args:
        payload: Dictionary containing profile information

    Returns:
        API response with status code and body
    """
    try:
        # Extract and validate required fields
        user_type = payload.get('user_type')
        if user_type not in ['Professional', 'Contractor']:
            return {
                'statusCode': 400,
                'body': json.dumps({'error': "user_type must be 'Professional' or 'Contractor'"})
            }

        # Handle is_from_bot safely (convert string to boolean if necessary)
        is_from_bot = payload.get('is_from_bot', True)
        if isinstance(is_from_bot, str):
            is_from_bot = is_from_bot.lower() == 'true'

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
            'is_from_bot': is_from_bot,
        }

        # Generate business card image
        image_bytes = generate_business_card(profile_data)

        # Resize image to 300x150 before uploading
        image = Image.open(BytesIO(image_bytes))
        image = image.resize((300, 150), Image.Resampling.LANCZOS)
        buffer = BytesIO()
        image.save(buffer, format='PNG')
        image_bytes = buffer.getvalue()

        # Upload to Google Cloud Storage
        url = upload_to_gcs(image_bytes)

        # Return success with URL
        return {
            'statusCode': 200,
            'body': json.dumps({
                'success': True,
                'url': url,
            })
        }

    except Exception as e:
        print(f"[ERROR] Failed to create profile card: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }