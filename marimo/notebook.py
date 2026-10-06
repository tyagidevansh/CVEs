import marimo

__generated_with = "0.20.4"
app = marimo.App()


@app.cell
def _():
    import marimo as mo

    mo.md(
        """
        # Lab notebook

        This is just a placeholder notebook so the marimo server runs in
        **edit mode**.
        """
    )
    return (mo,)


@app.cell
def _():
    answer = 6 * 7
    answer
    return (answer,)


if __name__ == "__main__":
    app.run()
