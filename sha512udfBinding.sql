-- DROP FUNCTION SHA512;
CREATE FUNCTION SHA512 (VARCHAR(255))
RETURNS CHAR(128)
EXTERNAL NAME 'udfhash!sha512'
LANGUAGE C
PARAMETER STYLE SQL
DETERMINISTIC
NOT FENCED                                      -- May want to change this value
CALLED ON NULL INPUT
NO SQL
PROGRAM TYPE SUB
NO EXTERNAL ACTION;
