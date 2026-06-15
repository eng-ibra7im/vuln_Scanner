import sys

filepath = r"d:\vuln_Scanner\web\web_interface.html"
with open(filepath, 'r', encoding='utf-8') as f:
    content = f.read()

content = content.replace(
    '<option value="25">25</option>\n                                <option value="50" selected>50</option>',
    '<option value="25" selected>25</option>\n                                <option value="50">50</option>'
)

with open(filepath, 'w', encoding='utf-8') as f:
    f.write(content)
