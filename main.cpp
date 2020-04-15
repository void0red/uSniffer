#include <QApplication>
#include "view.h"

int main(int argc, char *argv[]) {
    QApplication a(argc, argv);
    view viewer;
    viewer.show();
    return a.exec();
}