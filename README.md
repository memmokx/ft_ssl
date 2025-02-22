# ft_ssl

## Dependencies

- A C compiler that supports C23 
- **Optional**: Criterion

## Building

### Subject binary (`ft_ssl`)

```shell
make
```

### Shared library (`libfssl.so`)
```shell
make lib
```

## Unit Testing

Simply run `make test`

## Subjects

Subjects branch are named `subject/<subject_name>`.
If you wish to review `ft_ssl_md5` files only:
```shell
git checkout subject/ft_ssl_md5
```