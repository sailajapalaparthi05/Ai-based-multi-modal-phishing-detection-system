from PIL import Image, ImageDraw, ImageFont
import os

def create_icon(size, color):
    """Create a simple shield icon for the Chrome extension"""
    # Create a new image with transparent background
    img = Image.new('RGBA', (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    
    # Draw shield shape
    margin = size // 8
    shield_width = size - 2 * margin
    shield_height = int(shield_width * 1.2)
    
    # Shield points
    points = [
        (margin, margin),  # Top left
        (size - margin, margin),  # Top right
        (size - margin, margin + shield_height // 2),  # Right middle
        (size // 2, margin + shield_height),  # Bottom
        (margin, margin + shield_height // 2),  # Left middle
    ]
    
    # Draw shield
    draw.polygon(points, fill=color, outline=(255, 255, 255, 255), width=2)
    
    # Draw checkmark
    check_size = size // 4
    check_x = size // 2 - check_size // 2
    check_y = size // 2 - check_size // 3
    
    # Checkmark points
    check_points = [
        (check_x, check_y + check_size // 2),
        (check_x + check_size // 3, check_y + check_size),
        (check_x + check_size, check_y),
    ]
    
    draw.line(check_points, fill=(255, 255, 255, 255), width=max(2, size // 16))
    
    return img

# Create icons in different sizes
colors = {
    'icon16.png': (56, 189, 248, 255),   # Light blue
    'icon48.png': (56, 189, 248, 255),   # Light blue
    'icon128.png': (56, 189, 248, 255),  # Light blue
}

icons_dir = os.path.dirname(os.path.abspath(__file__))

for filename, color in colors.items():
    size = int(filename.replace('icon', '').replace('.png', ''))
    icon = create_icon(size, color)
    icon.save(os.path.join(icons_dir, filename))
    print(f"Created {filename}")

print("Icons generated successfully!")