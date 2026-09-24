#include "MyForm.h"
#include "ctime"
#include "cmath"
#include "cstdlib"

using namespace System;
using namespace System::Windows::Forms;
using namespace System::ComponentModel;
using namespace System::Collections;
using namespace System::Data;
using namespace System::Drawing;

/// <summary>
/// </summary>
/// <param name="args"></param>
/// <returns></returns>

int main(array<String^>^ args) {
	Application::SetCompatibleTextRenderingDefault(false); // Настройка текста по умолчанию выключено//
	Application::EnableVisualStyles(); //Разрешение визуальных стилей//
	shipherface::MyForm form; //Создание обьекта//
	Application::Run(% form); //Без % оно может выдать ошибку т.к это ссылочный класс (static void)//
}