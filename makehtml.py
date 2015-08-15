import os
import Graphics

filename = os.path.join(os.path.abspath(os.path.dirname(__file__)),
                        'TRS81-3krl.png')
font = Graphics.Picture(filename)
index = 0
for row in range(0, font.height, 24):
    for col in range(0, font.width, 16):
        image = font.getRegion((col,row), 16, 24)
        image.savePicture("ascii-%d.png" % index)
        index += 1


fp = open("table.html", "w")
fp.write('<body bgcolor="#999999">\n')
fp.write("<table>\n")
i = 0
while i < 256:
    fp.write('<tr>')
    for cols in range(16):
        fp.write('<td align="right">%d</td><td><img src="ascii-%d.png"></a></td>\n' % (i, i))
        i += 1
    fp.write('</tr>')
fp.write("</table>\n")
fp.write("</body>\n")
fp.close()
