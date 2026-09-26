#pragma once

// Нативные заголовки для алгоритма SPN и утилит
#include <string>
#include <vector>
#include <array>
#include <random>
#include <functional>
#include <sstream>
#include <cstdint>
#include <msclr/marshal_cppstd.h>

namespace shipherface {

	using namespace std;
	using namespace System;
	using namespace System::ComponentModel;
	using namespace System::Collections;
	using namespace System::Windows::Forms;
	using namespace System::Data;
	using namespace System::Drawing;

	// --- Нативные реализации SPN и утилиты (внутри anon namespace чтобы не засорять глобал) ---
	namespace {
		static std::mt19937 gen((std::random_device())());

		std::string bytesToBits(const std::string& s) {
			std::string bits; bits.reserve(s.size() * 8);
			for (unsigned char c : s)
				for (int i = 7; i >= 0; --i)
					bits.push_back(char('0' + ((c >> i) & 1)));
			return bits;
		}
		std::string bitsToBytes(const std::string& bits) {
			if (bits.size() % 8) return {};
			std::string out; out.reserve(bits.size() / 8);
			for (size_t i = 0; i < bits.size(); i += 8) {
				unsigned char v = 0;
				for (size_t j = 0; j < 8; ++j) v = (v << 1) | (bits[i + j] - '0');
				out.push_back(char(v));
			}
			return out;
		}
		std::string xorBits(const std::string& a, const std::string& b) {
			if (a.size() != b.size()) return {};
			std::string out; out.reserve(a.size());
			for (size_t i = 0; i < a.size(); ++i) out.push_back(a[i] == b[i] ? '0' : '1');
			return out;
		}
		std::string randomKey64() {
			std::uniform_int_distribution<> d(0, 1);
			std::string k; k.reserve(64);
			for (int i = 0; i < 64; ++i) k.push_back(char('0' + d(gen)));
			return k;
		}
		std::string applySBox(const std::string& bits, const std::array<int, 16>& sbox) {
			if (bits.size() % 4) return {};
			std::string out; out.reserve(bits.size());
			for (size_t i = 0; i < bits.size(); i += 4) {
				int v = 0;
				for (size_t j = 0; j < 4; ++j) v = (v << 1) | (bits[i + j] - '0');
				int m = sbox[v] & 0xF;
				for (int b = 3; b >= 0; --b) out.push_back(char('0' + ((m >> b) & 1)));
			}
			return out;
		}
		std::array<int, 16> invertSBox(const std::array<int, 16>& sbox) {
			std::array<int, 16> inv{};
			inv.fill(0);
			for (int i = 0; i < 16; ++i) inv[sbox[i] & 0xF] = i;
			return inv;
		}
		std::string applyPBox(const std::string& bits, const std::vector<int>& pbox) {
			if (bits.size() != pbox.size()) return {};
			std::string out(bits.size(), '0');
			for (size_t i = 0; i < pbox.size(); ++i) out[i] = bits[pbox[i]];
			return out;
		}
		std::vector<int> invertPBox(const std::vector<int>& pbox) {
			std::vector<int> inv(pbox.size(), -1);
			for (size_t i = 0; i < pbox.size(); ++i) inv[pbox[i]] = static_cast<int>(i);
			return inv;
		}
		std::vector<std::string> buildRoundKeys(const std::string& master, int rounds) {
			uint64_t seed = static_cast<uint64_t>(std::hash<std::string>{}(master));
			std::mt19937_64 rng(seed);
			std::vector<std::string> keys; keys.reserve(rounds + 1);
			for (int i = 0; i <= rounds; ++i) {
				uint64_t v = rng();
				std::string k; k.reserve(64);
				for (int b = 63; b >= 0; --b) k.push_back(((v >> b) & 1) ? '1' : '0');
				keys.push_back(k);
			}
			return keys;
		}

		string To_str(string& bits) {
			string s;
			int len = bits.size();
			for (int i = 0; i < bits.size(); i += 8) {
				int num = 0;
				for (size_t j = 0; j <= 7; j++)
				{
					num += ((bits[i + j] - '0') * (pow(2, 7 - j)));


				}
				s.push_back(static_cast<char>(num));

			}
			return s;

		}


		// Возвращаем весь лог в std::string (чтобы показать в GUI)
		std::string spnEncryptLog(const std::string& pt, const std::vector<std::string>& keys,
			int rounds, const std::array<int, 16>& sbox, const std::vector<int>& pbox)
		{
			std::ostringstream log;
			std::string state = xorBits(pt, keys[0]);
			log << "Round 0 (after XOR K0) : " << state << '\n';
			for (int r = 1; r < rounds; ++r) {
				state = applySBox(state, sbox);
				state = applyPBox(state, pbox);
				state = xorBits(state, keys[r]);
				log << "Round " << r << "                : " << state << '\n';
			}
			state = applySBox(state, sbox);
			state = xorBits(state, keys[rounds]);
			log << "Round " << rounds << " (cipher)     : " << state << '\n';
			log << "CIPHER_BITS:" << state << '\n'; // маркер для получения шифртекста
			return log.str();
		}
		std::string spnDecryptLog(const std::string& ct, const std::vector<std::string>& keys,
			int rounds, const std::array<int, 16>& invS, const std::vector<int>& invP)
		{
			std::ostringstream log;
			std::string state = xorBits(ct, keys[rounds]);
			state = applySBox(state, invS);
			log << "Dec Round " << rounds << "         : " << state << '\n';
			for (int r = rounds - 1; r >= 1; --r) {
				state = xorBits(state, keys[r]);
				state = applyPBox(state, invP);
				state = applySBox(state, invS);
				log << "Dec Round " << r << "         : " << state << '\n';
			}
			state = xorBits(state, keys[0]);
			log << "Dec Round 0               : " << state << '\n';
			log << "RECOVERED_BITS:" << state << '\n';
			return log.str();
		}

		// Извлечь ровно expectedLen битов ('0'/'1') следуя за маркером.
		std::string extractBits(const std::string& log, const std::string& marker, size_t expectedLen = 64) {
			auto pos = log.find(marker);
			if (pos == std::string::npos) return {};
			size_t i = pos + marker.size();
			std::string bits;
			bits.reserve(expectedLen);
			for (; i < log.size() && bits.size() < expectedLen; ++i) {
				char c = log[i];
				if (c == '0' || c == '1') bits.push_back(c);
			}
			return bits;
		}
	}
		

	/// <summary>
	/// Сводка для MyForm
	/// </summary>
	public ref class MyForm : public System::Windows::Forms::Form
	{
	public:
		MyForm(void)
		{
			InitializeComponent();
		}

	protected:
		~MyForm()
		{
			if (components)
			{
				delete components;
			}
		}
	private: System::Windows::Forms::Button^ button1;
	private: System::Windows::Forms::Label^ label1;
	protected:

	private:
		System::ComponentModel::Container^ components;

#pragma region Windows Form Designer generated code
		void InitializeComponent(void)
		{
			this->button1 = (gcnew System::Windows::Forms::Button());
			this->label1 = (gcnew System::Windows::Forms::Label());
			this->SuspendLayout();
			// 
			// button1
			// 
			this->button1->Location = System::Drawing::Point(499, 351);
			this->button1->Name = L"button1";
			this->button1->Size = System::Drawing::Size(120, 40);
			this->button1->TabIndex = 0;
			this->button1->Text = L"Зашифровать";
			this->button1->UseVisualStyleBackColor = true;
			this->button1->Click += gcnew System::EventHandler(this, &MyForm::button1_Click);
			// 
			// label1
			// 
			this->label1->AutoSize = true;
			this->label1->Location = System::Drawing::Point(90, 47);
			this->label1->Name = L"label1";
			this->label1->Size = System::Drawing::Size(44, 16);
			this->label1->TabIndex = 1;
			this->label1->Text = L"label1";
			// 
			// MyForm
			// 
			this->AutoScaleDimensions = System::Drawing::SizeF(8, 16);
			this->AutoScaleMode = System::Windows::Forms::AutoScaleMode::Font;
			this->ClientSize = System::Drawing::Size(800, 450);
			this->Controls->Add(this->label1);
			this->Controls->Add(this->button1);
			this->Name = L"MyForm";
			this->Text = L"MyForm";
			this->Load += gcnew System::EventHandler(this, &MyForm::MyForm_Load);
			this->ResumeLayout(false);
			this->PerformLayout();

		}
#pragma endregion
	private: System::Void MyForm_Load(System::Object^ sender, System::EventArgs^ e) {
		this->label1->Text = L"Нажмите «Зашифровать» чтобы выполнить пример SPN";
	}
	private: System::Void button1_Click(System::Object^ sender, System::EventArgs^ e) {
		// Параметры алгоритма
		const int rounds = 8;
		const std::string plaintext = "testtest"; // ровно 8 байт = 64 бита
		const std::array<int, 16> sbox = {
			0xE,0x4,0xD,0x1,
			0x2,0xF,0xB,0x8,
			0x3,0xA,0x6,0xC,
			0x5,0x9,0x0,0x7
		};
		const std::array<int, 16> invS = invertSBox(sbox);
		std::vector<int> pbox(64);
		for (int i = 0; i < 64; ++i) pbox[i] = (i % 8) * 8 + (i / 8);
		const std::vector<int> invP = invertPBox(pbox);

		// Подготовка: битовое представление
		std::string ptBits = bytesToBits(plaintext);
		std::string master = randomKey64();
		auto roundKeys = buildRoundKeys(master, rounds);

		// Выполняем шифрование и получаем лог
		std::string encryptLog = spnEncryptLog(ptBits, roundKeys, rounds, sbox, pbox);

		// Извлекаем шифртекст из лога (метка CIPHER_BITS:) — только '0'/'1', ровно 64 бита
		std::string cipherBits = extractBits(encryptLog, "CIPHER_BITS:", 64);
		if (cipherBits.size() != 64) {
			MessageBox::Show("Не удалось корректно извлечь шифртекст (ожидалось 64 бита).", "Ошибка", MessageBoxButtons::OK, MessageBoxIcon::Error);
			return;
		}

		// Показать результат шифрования в окне (в label и диалоге)
		System::String^ outText = msclr::interop::marshal_as<System::String^>(encryptLog);
		this->label1->Text = outText;



		// Спросим пользователя — расшифровать ли
		auto res = MessageBox::Show("Выполнить расшифровку?", "SPN", MessageBoxButtons::YesNo, MessageBoxIcon::Question);
		if (res == System::Windows::Forms::DialogResult::Yes) {
			std::string decryptLog = spnDecryptLog(cipherBits, roundKeys, rounds, invS, invP);
			System::String^ decText = msclr::interop::marshal_as<System::String^>(decryptLog);




			// Покажем лог расшифровки
			this->label1->Text = decText;
			// Также уведомим, совпало ли восстановленное состояние с исходным
			std::string recoveredBits = extractBits(decryptLog, "RECOVERED_BITS:", 64);
			this->label1->Text += "Расшифрованный текст:   " + msclr::interop::marshal_as<System::String^>(To_str(recoveredBits));
			if (recoveredBits.size() != 64) {
				MessageBox::Show("Не удалось корректно извлечь восстановленные биты.", "Ошибка", MessageBoxButtons::OK, MessageBoxIcon::Error);
				return;
			}
			bool equal = (recoveredBits == ptBits);
			std::string message = std::string("Recovered equals original: ") + (equal ? "Yes" : "No");
			if (equal) message += "\nRecovered text: " + bitsToBytes(recoveredBits);
			MessageBox::Show(msclr::interop::marshal_as<System::String^>(message), "SPN result", MessageBoxButtons::OK, MessageBoxIcon::Information);
		}
		else {
			MessageBox::Show("Расшифровка пропущена по запросу пользователя.", "SPN", MessageBoxButtons::OK, MessageBoxIcon::Information);
		}
	}
	private: System::Void label1_Click(System::Object^ sender, System::EventArgs^ e) {
		// можно использовать для копирования/расширенного показа
	}
	};
}