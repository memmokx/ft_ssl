# ft_ssl

## Dependencies

- A C compiler that supports C23
- **Optional**: Criterion: to run `fssl` tests.
- **Optional**: LLVM lit & FileCheck: to run the cli test suite.

## Building

### Subject binary (`ft_ssl`)

```shell
make
```

### Shared library (`libfssl.so`)

```shell
make lib
```

## Testing

Prior to testing make sure to have a clean build by running `make fclean`.

*Recommended*: To enable the sanitizers add `SANITIZE=1`.

### Unit testing

Simply run `make test`. Requires `Criterion`

### Integration testing

Simply run `make lit-test`. Requires `lit` & `FileCheck`

## Subjects

Subjects branch are named `subject/<subject_name>`.
If you wish to review `ft_ssl_md5` files only:

```shell
git checkout subject/ft_ssl_md5
```
