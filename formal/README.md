تجريبي، غير مدقق، لا يُستخدم لحماية بيانات حقيقية

# Formal model — SHC-Guard v0.6 (Tamarin)

## الملفات

| الملف | المحتوى |
|---|---|
| `shc_guard.spthy` (544 سطرًا) | النموذج الكامل: الحقبات المنفصلة، سلسلة CP عبر `prev_cp_hash`، `anchor_head`، دورة حياة التحدي لكل اتجاه، الجيل. 10 lemmas. |
| `shc_guard_bounded.spthy` (540 سطرًا) | نسخة محدودة الجلسات (≤2 جلسة، عدد رسائل صغير) من النموذج نفسه، لمحاولة الإثبات على جهاز صغير. |
| `tamarin-prover` + `maude` + `prelude.maude` | **غير مضمَّنة في هذا المستودع** (ثنائيات كبيرة: Tamarin 1.12.0 وMaude 3.5.1). نزّلها من الموقع الرسمي لـ Tamarin وMaude، وضعها في هذا المجلد، ثم اتبع «كيف تعيد المحاولة» أدناه. `prelude.maude` ملف نصي مضمَّن هنا. |

## حالة التحقق — NOT machine-checked / لم يُتحقق منه آليًا

**لم يُثبَت أي lemma ولم يُدحَض أي lemma.** صفر براهين مكتملة. لا يُقدَّم هذا النموذج كتحقق رسمي.

المحاولات الموثقة على هذا الجهاز (2026-11-16):

1. وكيل النموذج الرسمي شغّل محاولات إثبات ~15 دقيقة (878 ثانية من عمر الوكيل، وعملية Tamarin ما زالت جارية عند آخر فحص) دون إكمال أي lemma. أُوقف العمل بأمر المستخدم («اسرع»: لا يُسمح لـ Tamarin بحجب التسليم).
2. محاولتي أنا (المنسّق) على النسخة المحدودة: `./tamarin-prover --prove=message_key_secrecy shc_guard_bounded.spthy` بمهلة 120 ثانية — النظرية تُحمَّل وتُترجَم وتُغلق (`Theory loaded / translated / closed`)، لكن بحث الإثبات لم ينتهِ خلال 120 ثانية.

## عقبتان بيئيتان اكتُشفتا أثناء المحاولة (لمن يعيد التشغيل)

- Maude غير موجود في `PATH` افتراضيًا: يجب تشغيل Tamarin مع `PATH=<formal-dir>:$PATH` وإلا فشل فورًا برسالة `Maude is not installed`.
- الملف يحوي تعليقات عربية: يجب تعيين `LC_ALL=C.UTF-8 LANG=C.UTF-8` وإلا فشل التحميل بخطأ فك ترميز (`hGetContents: invalid argument (cannot decode byte sequence...)`).

## كيف تعيد المحاولة

```bash
cd /home/hatch/workspace/shc-guard-v06/formal
LC_ALL=C.UTF-8 LANG=C.UTF-8 PATH=$PWD:$PATH \
  timeout 600 ./tamarin-prover --prove=message_key_secrecy shc_guard_bounded.spthy
```

للإثبات الكامل يلزم جهاز بذاكرة ووقت أكبر، أو تقييد النموذج أكثر (جلسة واحدة، رسائل أقل).
