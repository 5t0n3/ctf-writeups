# bounce_the_flag

## Challenge description

> Let's kick things off with one of my favorite classic games: Bounce the Flag! Bounce the flag is an immersive hyper-realistic gaming experience that involves bouncing a flag on a green rectangle. One of Bounce the Flag's most celebrated competitors, Mr. Flag once managed a score of 31337 points in a single round. No one knows how he did it - not even Mr. Flag himself, because he has amnesia and he forgot... He also forgot the password to his account... Maybe you can help him out?

## Solution

### Gameplay

Bounce the Flag is a truly riveting game, but unfortunately it's really easy to lose. When that inevitably happens, you're presented with a login screen to record your score:

<div align="center">
<img src="img/loss.png" alt="Post-game-over login screen">
</div>

Unfortunately we weren't given a username and password, but we *were* given the source code of the Flask server that handles authentication. After perusing web/app.py, I found this on lines 59-69:

```python
        res = sql_fetchall(
            connection,
            f"""
            SELECT score, game_time
            FROM users
            INNER JOIN games
            ON users.id = games.user_id
            WHERE username = '{username}' AND password = '{password}'
            ORDER BY game_time
            """
        )
```

Instead of properly using MySQL's parameter system, the username and password entered by the user are directly interpolated into an f-string that is passed as a request to the MySQL database. This allows the user to execute arbitrary SQL with a carefully crafted username or password. This can be tested by entering a single quote as a username and trying to log in, which does end up displaying a SQL error:

<div align="center">
  <img src="img/sql-error.png" alt="SQL syntax error on login screen">
</div>

This confirms that SQL injection is possible. Now it's only a matter of crafting the right query to get the flag.

### Crafting a query

Because of the `WHERE` clause present in this query, we know that there is a `password` column in the `users` table, and we also know that the passwords are stored as plain text because of the direct equality comparison. I decided to inject SQL into the password field when logging in because it made more sense in my head, but you could also inject into the username field if you wanted.

Obviously the password would have to start with a single quote to close off the string started where it's interpolated. Since we're trying to get Mr. Flag's password, we have to execute another query to fetch that from the `users` table. This can be accomplished via the `UNION` operator, which takes a `SELECT` statement on either side and joins the results. We can't just select the password, though, since the `UNION` operator requires that both `SELECT` statements have the same number of columns. I opted to select the `password` column twice, but any other column would work alongside the `password` column. Combining all of this into a single payload yields the following:

```txt
' or 1=1 UNION SELECT password, password FROM users WHERE username = 'Mr. Flag' -- 
```

Note that there is a space after the comment. When this is submitted as a password (as well as Mr. Flag for the username), the database query from above turns into this (breaking up lines for readability):

```sql
SELECT score, game_time
    FROM users
    INNER JOIN games
    ON users.id = games.user_id
    WHERE username = 'Mr. Flag' 
    AND password = '' or 1=1 
    UNION SELECT password, password 
    FROM users 
    WHERE username = 'Mr. Flag' 
    -- ORDER BY game_time
```

Instead of getting the password, though, you get a message about having a low score?

<div align="center">
  <img src="img/no-score.png" alt="Message about not having high enough score">
</div>

### Getting that 1337 score

Obviously you could sit there and try to get a score of 1337 or higher, but that would take forever and would probably be boring (sorry Bounce the Flag). I decided to look at the JavaScript that handles a login attempt in web/static/game.js, part of which is the following:

```js
function login_pressed() {
    createPostRequest(
        {
            username: document.getElementById("username_input").value,
            password: document.getElementById("password_input").value,
            score: score
        },
        "/login",
        () => {
            let f = document.getElementById("login");
            f.action = "/login";
            f.submit();
        }
    );
}
```

It turns out `score` is defined as a global variable at the very top of game.js, so you can just set it directly from the browser console: `score = 1337` (or anything greater than that). After doing so, attempting to log in again after dying brings us to the scoreboard as well as shows us the flag: `osu{Py7h0n_F_s7r1n9S_4Re_8E4u71FuL_4ND_4M421N9}`

Python f-strings are cool when used correctly, but not when used to construct SQL queries from unescaped user input :)
