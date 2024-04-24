# pgrx-ed25519 (ped25519)

ed25519 sign/verify PSQL extension.

This is a Rust analog of: https://www.freshports.org/databases/pg_ed25519


Usage:

```
ped25519=# create extension ped25519;                      
CREATE EXTENSION
ped25519=# SELECT ed25519_verify(                                      
               bytea 'some data for signing',                                                                                                          
               ed25519_sign(                                                        
                       bytea 'some data for signing',
                       decode('NZV4l8hck3iUqInENyI+nn5vkW7rqzQg0uiuuZkPnHE=', 'base64'),
                       decode('eT7qaT8vkIgCl6/9EmEDYYEgxA0oOgHc0P6UYzcQN28=', 'base64')
                   ),
               decode('NZV4l8hck3iUqInENyI+nn5vkW7rqzQg0uiuuZkPnHE=', 'base64')
           );
 ed25519_verify 
----------------
 t
(1 row)

```
