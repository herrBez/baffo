# Contributing to Baffo

We welcome contributions of all kinds—bug reports, feature requests, documentation improvements, and code contributions!  

By contributing, you agree to follow the [Contributor Covenant Code of Conduct](https://www.contributor-covenant.org/).

---

## Documentation

The current documentation is minimal and mainly corresponds to the comments in the source code. 

## How to Contribute

1. **Fork the repository**  

2. **Clone your fork**  

   ```bash
   git clone https://github.com/your-username/baffo.git
   cd baffo
   ```

3. Create a new branch for your work:

   ```bash
   git checkout -b feature/my-feature
   ```

4. Make your changes
   - Code improvements or new features
   - Tests for new functionality or bug fixes
   - Documentation enhancements

> 💡 If you want to know more about the transpile command and its inner working, check out the [transpile README](https://github.com/herrBez/baffo/tree/master/internal/app/transpile)

5. Run tests to ensure everything works

   ```bash
   go test ./...
   ```

6. Commit your changes
   ```bash
   git add .
   git commit -m "Add my feature"
   ```
   
7. Push your branch
   ```
   git push origin feature/my-feature
   ```

8. Open a pull request on Github
   - Clearly describe what your PR does
   - Link any related issues


## Reporting Issues

If you encounter bugs or have feature requests:

- Open an issue on GitHub Issues
- Provide clear reproduction steps, logs, or example pipelines if possible

## Guidelines

Follow the existing code style and formatting

- Write tests for any new functionality or bug fixes
- Keep commits small, atomic, and descriptive
- For major changes, open an issue first to discuss your plan



Thank you for helping improve Baffo! Your contributions make the project stronger and more useful for everyone.