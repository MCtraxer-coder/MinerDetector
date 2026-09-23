from gui import MinerDetectorApp
def main():
    app = MinerDetectorApp()
    app.protocol("WM_DELETE_WINDOW", app.on_closing)
    app.mainloop()


if __name__ == "__main__":
    main()