__author__ = 'austin'
# will be capable of exporting scans to different file types
import tkinter as tk
import tkinter.filedialog
import pickle
import socket

# need to add support for clean csv xml txt
# the dictionary nesting could be cleaned up a little bit when exporting as human readable data

class Export:
    @staticmethod
    def ask_save_as():
        save_as = [('json', '.json'), ('pickle', '.p')]
        file = tk.filedialog.asksaveasfile(filetypes=save_as)
        try:
            x, y = file.name.split('.')
        except AttributeError:  # caused by user closing the window without
            exit(0)
        data = {}
        f = open('results.p', 'rb')
        while True:
            try:
                data.update(pickle.load(f))
            except EOFError:
                break
        f.close()
        sdata = sorted(data.items(), key=lambda item: socket.inet_aton(item[0]))
        if y == 'json':
            Export.to_json(data, file)
        elif y == 'p':
            Export.to_pickle(data, file)
        else:
            pass
        file.close()
        exit(0)

    @staticmethod
    def to_json(data, file):
        import json
        json.dump(data, file, indent=4, sort_keys=True)

    @staticmethod
    def to_pickle(data, file):
        pickle.dump(data, file)

def main():
    Export.ask_save_as()

if __name__ == "__main__":
    main()