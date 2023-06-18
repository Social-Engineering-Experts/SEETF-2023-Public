import sqlite3
con = sqlite3.connect("user.db", check_same_thread=False)
con.isolation_level = None

cur = con.cursor()
cur.execute("""
    DROP TABLE IF EXISTS users;
""")
cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        dXNlcm5hbWVpbmJhc2U2NA TEXT NOT NULL PRIMARY KEY,
        cGFzc3dvcmRpbmJhc2U2NA TEXT NOT NULL
    );
""")
cur.execute("""
    INSERT INTO users (dXNlcm5hbWVpbmJhc2U2NA, cGFzc3dvcmRpbmJhc2U2NA) 
    VALUES ('admin', 'SEE{5q1I_tH3n_55Ti_cH4In3D_3xpLi0t}');
""")