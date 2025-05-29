# ft_ssl

## Dependencies

- A C compiler that supports C23
- **Optional**: Criterion: to run `fssl` tests.
- **Optional**: [litcheck](https://github.com/bitwalker/litcheck): to run the cli test suite.

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

### Unit testing

Simply run `make test`. Requires `Criterion`

### Integration testing

Simply run `make lit-test`. Requires `litcheck`

## Subjects

Subjects branch are named `subject/<subject_name>`.
If you wish to review `ft_ssl_md5` files only:

```shell
git checkout subject/ft_ssl_md5
```
