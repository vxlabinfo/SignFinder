# SignFinder
Tool for easy clean PE32 from AV signature 
 
# Manual [RU]
**SignFinder** - утилита для быстрого поиска сигнатур антивирусов в pe32 файлах

## Update
Софт постепенно обновляется

27.07.16:
* Новый парсер аргументов, изменён их порядок. 
* Отдельная папка для каждого режима, в имени которой отражены аргументы
* Добавлен режим info

## Пример работы
Можно посмотреть на [youtube](https://www.youtube.com/watch?v=5I6HMdZfoE8)

## Info mode
Информация о секциях, в пригодной для софта системе счисления.

	python SF.py path_to_exe info

## Fast mode
Быстрый режим призван определить какого толка сигнатура нас беспокоит:
* Эмулятора
* Импорта
* Секций

Создаются следующие типы файлов:
* ALL_SECTION - стёрты все секции
* ALL_SECTION_NOT[0].text - стёрты все секции кроме первой, под именем .text
* SECTION[2].data - стёрта только третья секция, под именем .data
* EMUL - на точку входа эмулятора поставлен выход. Он прекратит свою работу и детект эмулятора исчезнет.
* IMPORT - весь импорт перезатёрт - если сигнатура стояла на импорте - она пропадёт.

	python SF.py path_to_exe fast

## Header mode
Методом исключения, если затирание секций оставляет детект - сигнатура стоит на оставшихся заголовках pe32. Данный режим затирает каждое поле по отдельности, создавая файлы типа:

* IMAGE_DOS_HEADER-e_cblp
* IMAGE_OPTIONAL_HEADER-AddressOfEntryPoint

	python SF.py path_to_exe head

## Section mode
Это режим работы с конкретной секцией, она делится на 100 участков одинакового размера и в каждом файле стёрт свой участок. Указывается порядковый номер секции.

	python SF.py path_to_exe sect section_number
	python SF.py path_to_exe sect section_number -p 100

## Manual mode
Режим ручного управления. Заданный в параметрах участок, делится на заданное количество частей, каждая перезатирается по очереди. Длина шага равна размеру одной части.

Например, было:

	FF FF FF FF FF FF 
Стало:

	00 00 FF FF FF FF 	
	FF FF 00 00 FF FF 	
	FF FF FF FF 00 00

	python SF.py path_to_exe man offset size part_num

## Manual2 mode
Второй ручной режим, отличается от первого длиной шага, который равен одному байту.

Например, было:

	FF FF FF FF FF FF 
Стало:

	00 00 FF FF FF FF 
	FF 00 00 FF FF FF 
	FF FF 00 00 FF FF 

	SF.py path_to_exe man2 offset size window_size

